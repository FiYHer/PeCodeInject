;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.386
		.model flat, stdcall
		option casemap :none
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Include 文件定义
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
include		windows.inc;

include		user32.inc
includelib	user32.lib

include		kernel32.inc
includelib	kernel32.lib

include		comdlg32.inc
includelib	comdlg32.lib
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; Equ 等值定义
;就是相当C语言的define
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
ICO_MAIN	equ	1000
DLG_MAIN	equ	1000
IDC_INFO	equ	1001
IDM_MAIN	equ	2000
IDM_OPEN	equ	2001
IDM_EXIT	equ	2002
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 数据段
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		.data?
hInstance	dd	?;程序的实例
hRichEdit	dd	?;编辑框控件句柄
hWinMain	dd	?;主窗口句柄
hWinEdit	dd	?;编辑框控件句柄
szFileName	db	MAX_PATH dup (?);文件字符串 260长度

		.const
szDllEdit	db	'RichEd20.dll',0
szClassEdit	db	'RichEdit20A',0
szFont		db	'宋体',0
szExtPe		db	'PE Files',0,'*.exe;*.dll;*.scr;*.fon;*.drv',0
		db	'All Files(*.*)',0,'*.*',0,0
szErr		db	'文件格式错误!',0
szErrFormat	db	'这个文件不是PE格式的文件!',0
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 代码段
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

		.code
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;函数名 参数
_AppendInfo	proc	_lpsz
;局部变量
		local	@stCR:CHARRANGE

		pushad;保存所有的寄存器
		invoke	GetWindowTextLength,hWinEdit;获取编辑框的长度
		mov	@stCR.cpMin,eax;保存长度
		mov	@stCR.cpMax,eax;保存长度
		invoke	SendMessage,hWinEdit,EM_EXSETSEL,0,addr @stCR;获取字符
		invoke	SendMessage,hWinEdit,EM_REPLACESEL,FALSE,_lpsz;文本的替换
		popad;还原所有的寄存器
		ret;返回

_AppendInfo	endp;函数结束标志
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
include		_ProcessPeFile.asm;包含其它汇编文件
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
;函数名
_Init		proc
		local	@stCf:CHARFORMAT;局部变量

		invoke	GetDlgItem,hWinMain,IDC_INFO;获取指定控件的句柄
		mov	hWinEdit,eax;保存句柄
		invoke	LoadIcon,hInstance,ICO_MAIN;加载图标
		invoke	SendMessage,hWinMain,WM_SETICON,ICON_BIG,eax;设置图标
		invoke	SendMessage,hWinEdit,EM_SETTEXTMODE,TM_PLAINTEXT,0;设置模式
		invoke	RtlZeroMemory,addr @stCf,sizeof @stCf;清空局部变量
		
		;为字结构赋值
		mov	@stCf.cbSize,sizeof @stCf;获取局部变量的大小
		mov	@stCf.yHeight,9 * 20;设置高度
		mov	@stCf.dwMask,CFM_FACE or CFM_SIZE or CFM_BOLD;设置mask
		invoke	lstrcpy,addr @stCf.szFaceName,addr szFont;采用的字体名字
		invoke	SendMessage,hWinEdit,EM_SETCHARFORMAT,0,addr @stCf;/设置编辑框框架使用的字体信息
		invoke	SendMessage,hWinEdit,EM_EXLIMITTEXT,0,-1;设置上限
		ret

_Init		endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
; 错误 Handler
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_Handler	proc	_lpExceptionRecord,_lpSEH,_lpContext,_lpDispatcherContext

		pushad;保存所有寄存器
		mov	esi,_lpExceptionRecord;
		mov	edi,_lpContext
		assume	esi:ptr EXCEPTION_RECORD,edi:ptr CONTEXT
		mov	eax,_lpSEH
		push	[eax + 0ch]
		pop	[edi].regEbp
		push	[eax + 8]
		pop	[edi].regEip
		push	eax
		pop	[edi].regEsp
		assume	esi:nothing,edi:nothing
		popad
		mov	eax,ExceptionContinueExecution
		ret

_Handler	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_OpenFile	proc;打开文件
		local	@stOF:OPENFILENAME;打开文件结构体
		local	@hFile,@dwFileSize,@hMapFile,@lpMemory;文件句柄 文件大小 文件map 内存指针

		invoke	RtlZeroMemory,addr @stOF,sizeof @stOF;清空结构体的大小
		mov	@stOF.lStructSize,sizeof @stOF;设置结构体大小
		push	hWinMain
		pop	@stOF.hwndOwner;设置窗口句柄
		mov	@stOF.lpstrFilter,offset szExtPe;设置文件类型过滤
		mov	@stOF.lpstrFile,offset szFileName;保存文件路径地址
		mov	@stOF.nMaxFile,MAX_PATH;文件路径大小
		mov	@stOF.Flags,OFN_PATHMUSTEXIST or OFN_FILEMUSTEXIST;模式设置
		invoke	GetOpenFileName,addr @stOF;调用函数打开文件选择窗口
		.if	! eax
			jmp	@F
		.endif
;********************************************************************
; 打开文件并建立文件 Mapping
;********************************************************************
;;打开文件
		invoke	CreateFile,addr szFileName,GENERIC_READ,FILE_SHARE_READ or \
			FILE_SHARE_WRITE,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_ARCHIVE,NULL
		.if	eax !=	INVALID_HANDLE_VALUE
			mov	@hFile,eax
			invoke	GetFileSize,eax,NULL;获取文件大小
			mov	@dwFileSize,eax
			.if	eax
				invoke	CreateFileMapping,@hFile,NULL,PAGE_READONLY,0,0,NULL;创建文件map
				.if	eax
					mov	@hMapFile,eax
					invoke	MapViewOfFile,eax,FILE_MAP_READ,0,0,0;文件映射
					.if	eax
						mov	@lpMemory,eax
;********************************************************************
; 创建用于错误处理的 SEH 结构
;********************************************************************
						assume	fs:nothing
						push	ebp;?????
						push	offset _ErrFormat
						push	offset _Handler
						push	fs:[0]
						mov	fs:[0],esp
;********************************************************************
; 检测 PE 文件是否有效
;********************************************************************
						mov	esi,@lpMemory
						assume	esi:ptr IMAGE_DOS_HEADER
						.if	[esi].e_magic != IMAGE_DOS_SIGNATURE
							jmp	_ErrFormat
						.endif
						add	esi,[esi].e_lfanew
						assume	esi:ptr IMAGE_NT_HEADERS
						.if	[esi].Signature != IMAGE_NT_SIGNATURE
							jmp	_ErrFormat
						.endif
						invoke	_ProcessPeFile,@lpMemory,esi,@dwFileSize
						jmp	_ErrorExit
_ErrFormat:
						invoke	MessageBox,hWinMain,addr szErrFormat,NULL,MB_OK
_ErrorExit:
						pop	fs:[0]
						add	esp,0ch
						invoke	UnmapViewOfFile,@lpMemory
					.endif
					invoke	CloseHandle,@hMapFile
				.endif
				invoke	CloseHandle,@hFile
			.endif
		.endif
@@:
		ret

_OpenFile	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
_ProcDlgMain	proc	uses ebx edi esi hWnd,wMsg,wParam,lParam

		mov	eax,wMsg
		.if	eax == WM_CLOSE
			invoke	EndDialog,hWnd,NULL
		.elseif	eax == WM_INITDIALOG
			push	hWnd
			pop	hWinMain
			call	_Init
		.elseif	eax == WM_COMMAND
			mov	eax,wParam
			.if	ax ==	IDM_OPEN
				call	_OpenFile
			.elseif	ax ==	IDM_EXIT
				invoke	EndDialog,hWnd,NULL
			.endif
		.else
			mov	eax,FALSE
			ret
		.endif
		mov	eax,TRUE
		ret

_ProcDlgMain	endp
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
start:
		invoke	LoadLibrary,offset szDllEdit
		mov	hRichEdit,eax
		invoke	GetModuleHandle,NULL
		mov	hInstance,eax
		invoke	DialogBoxParam,hInstance,DLG_MAIN,NULL,offset _ProcDlgMain,NULL
		invoke	FreeLibrary,hRichEdit
		invoke	ExitProcess,NULL
;>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
		end	start
