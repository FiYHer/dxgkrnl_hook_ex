# dxgkrnl_hook_ex
以前改进的cheat内核通信模块,现在EAC Detected,现在发出来

# 别人版本的做法
在dxgkrnl.sys模块找到一个导出函数,修改函数前的汇编指令为mov eax,xxx  jmp eax
毫无疑问这个方法非常容易检测

# 我的版本做法
我的想法:在函数开始就是一个跳转指令太容易检测的话,那我把跳转指令放到函数返回的地方不就行了?将返回汇编替换为跳转到我们的函数!
好的,马上开始验证可行性!

我选择挂钩的导出函数(很多人都是挂钩这个的)
```c++
__int64 __fastcall NtOpenCompositionSurfaceSectionInfo(void *a1, unsigned __int64 *a2, __int64 *a3, __int64 a4)
```

我为什么选择这个函数呢?其实也是有讲究的,我们先看IDA出来的C代码
```c++
__int64 __fastcall NtOpenCompositionSurfaceSectionInfo(void *a1, unsigned __int64 *a2, __int64 *a3, __int64 a4)
{
  unsigned __int64 v4; // rdi
  void *v5; // r14
  signed int v6; // ebx
  unsigned __int64 v7; // rsi
  struct DXGGLOBAL *v8; // rax
  char v9; // r8
  PVOID Object; // [rsp+28h] [rbp-50h]
  unsigned __int64 v12; // [rsp+30h] [rbp-48h]
  __int64 v13; // [rsp+38h] [rbp-40h]
  __int64 v14; // [rsp+40h] [rbp-38h]
  __int128 v15; // [rsp+48h] [rbp-30h]
  __int64 v16; // [rsp+58h] [rbp-20h]
  CCompositionSurface *v17; // [rsp+88h] [rbp+10h]
  __int64 v18; // [rsp+98h] [rbp+20h]

  v18 = a4;
  v4 = a4;
  v5 = a1;
  v6 = 0;
  Object = 0i64;
  v7 = 0i64;
  v12 = 0i64;
  v13 = 0i64;
  v15 = 0ui64;
  v16 = 0i64;
  if ( a2 && a3 )
  {
    if ( a2 + 1 < a2 || (unsigned __int64)(a2 + 1) > *(_QWORD *)MmUserProbeAddress )
      a2 = *(unsigned __int64 **)MmUserProbeAddress;
    v7 = *a2;
    v12 = *a2;
    if ( a3 + 1 < a3 || (unsigned __int64)(a3 + 1) > *(_QWORD *)MmUserProbeAddress )
      a3 = *(__int64 **)MmUserProbeAddress;
    v14 = *a3;
    v13 = v14;
  }
  else
  {
    v6 = -1073741811;
  }
  KeEnterCriticalRegion();
  if ( v6 >= 0 )
  {
    v8 = DXGGLOBAL::GetGlobal();
    if ( (*(unsigned int (__cdecl **)(_QWORD))(*((_QWORD *)v8 + 38000) + 296i64))(*((_QWORD *)v8 + 38000)) )
    {
      v6 = CompositionSurfaceObject::ResolveHandle(v5, 1u, v9, (struct CompositionSurfaceObject **)&Object);
      if ( v6 >= 0 )
      {
        v17 = 0i64;
        v6 = CompositionSurfaceObject::LockForRead(Object, &v17);
        if ( v6 >= 0 )
        {
          v6 = CCompositionSurface::OpenSectionInfo(
                 v17,
                 v7,
                 (const struct CSM_SYSMEM_REALIZATION *)&v13,
                 (struct CSM_SYSMEM_SECTION_INFO *)&v15);
          CCompositionSurface::UnlockAndRelease(v17);
        }
        ObfDereferenceObject(Object);
      }
    }
    else
    {
      v6 = -1073741790;
    }
  }
  if ( v4 )
  {
    if ( v4 + 24 < v4 || v4 + 24 > *(_QWORD *)MmUserProbeAddress )
      **(_BYTE **)MmUserProbeAddress = 0;
    *(_OWORD *)v4 = v15;
    *(_QWORD *)(v4 + 16) = v16;
  }
  else
  {
    v6 = -1073741811;
  }
  KeLeaveCriticalRegion();
  return (unsigned int)v6;
}
```

我选做过函数的原因:
1.有void*参数,可以将我们用户层的数据传递下来(废话)
2.我们要在函数返回的地方跳转到我们的函数,a1 a2 a3 a4都是我们自定义传进来的,我们肯定希望这个函数的容错性越棒越好啊(防止出现意外情况导致蓝屏,例:如果我们传进来一个空指针,它不验证就去读取的话岂不是凉凉?)回到代码,我们可以看到  if ( a2 && a3 )   if ( v6 >= 0 )   if ( v4 )这几个判断,容错性非常好,我们传进来NULL的话它们什么都不执行,这正是我们想要的!
3.还是如上,到函数返回的地方了保存参数的寄存器里面的大概率不是参数了,所以我们要求函数保存了传进来的参数,不然也不好搞呀,我们可以看到 v5 = a1;真好,真的棒我们保存了参数！我们就可以用al这个参数传递数据进来了
4.函数返回处必须有足够的空间给我们写跳转指令,查找后发现是C3 CC CC CC CC CC CC CC CC CC  CC CC CC CC CC CC CC CC,一共0x12个字节,我们整个构造指令需要0x11字节!完美!

如上,我才会选择NtOpenCompositionSurfaceSectionInfo这个函数挂钩,可行性分析完毕,开始写代码!

第一步,找到NtOpenCompositionSurfaceSectionInfo函数地址
```c++
		void** dxgk_routine = reinterpret_cast<void**>(get_system_module_export("\\SystemRoot\\System32\\drivers\\dxgkrnl.sys", "NtOpenCompositionSurfaceSectionInfo"));
		if (dxgk_routine == nullptr) return;
		DbgPrintEx(0, 0, "[%s] NtOpenCompositionSurfaceSectionInfo address %p \n", __FUNCTION__, dxgk_routine);
```

第二步,定位函数返回地址,没什么可说就是定位c3 cc cc这三个汇编
```c++
		unsigned int i = 0;
		const unsigned char* byte_ptr = (const unsigned char*)dxgk_routine;
		for (i = 0; i < 0x200; i++)
		{
			if (byte_ptr[i] == 195 && byte_ptr[i + 1] == 204 && byte_ptr[i + 2] == 204)
				break;
		}
		
		if (i == 0x200) return;
		void** routine_ret = (void**)(byte_ptr + i);
		DbgPrintEx(0, 0, "[%s] Position %p \n", __FUNCTION__, routine_ret);
```

第三步,构造我们的跳转指令后写入
```c++
		unsigned char asms[] =
		{
			0x48,0xb8,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,// mov,rax,xxx
			0x49,0x8b,0x4b,0x08,// mov rcx, qword ptr ds:[r11+0x8] 还原a1参数
			0xff,0xe0,// jmp rax
			0xc3// ret
		};

		uintptr_t ptr = reinterpret_cast<uintptr_t>(function_address);
		memcpy((void*)((unsigned long long)asms + 2 * sizeof(unsigned char)), &ptr, sizeof(void*));
		write_to_read_only_memory(routine_ret, &asms, sizeof(asms));

		DbgPrintEx(0, 0, "[%s] Hook Finish \n", __FUNCTION__);
```

至此完毕,上机测试,效果完美

# 被检测
直接上游戏,两局后被禁
uc说会和文件字节码对比,所以强制删除dxgkrnl.sys再测,还是被禁
好吧,发布源码



