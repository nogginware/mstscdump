!IF "$(CFG)" == ""
CFG=Release32
!MESSAGE No configuration specified. Defaulting to Release32.
!ENDIF

!IF "$(USE_DETOURS)" == "1"
CFLAGS=/DUSE_DETOURS /IDetours-4.0.1\include
X86_LIBS=Detours-4.0.1\lib.X86\detours.lib
X64_LIBS=Detours-4.0.1\lib.X64\detours.lib
!ELSE
CFLAGS=/DUSE_DEVIARE /Ideviare
X86_LIBS=deviare\NktHookLib.lib
X64_LIBS=deviare\NktHookLib64.lib
!ENDIF

!IF "$(CFG)" == "Release32"
CFLAGS=/nologo /D_X86_ /EHsc /MT /Ox $(CFLAGS)
LIBS=advapi32.lib secur32.lib user32.lib ws2_32.lib $(X86_LIBS) legacy_stdio_definitions.lib
!ENDIF

!IF "$(CFG)" == "Release64"
CFLAGS=/nologo /D_AMD64_ /EHsc /MT /Ox $(CFLAGS)
LIBS=advapi32.lib secur32.lib user32.lib ws2_32.lib $(X64_LIBS)
!ENDIF

all: mstscdump.exe mstschook.dll test.exe

mstscdump.exe: mstscdump.cpp
  cl $(CFLAGS) mstscdump.cpp $(LIBS)

mstschook.dll: mstschook.cpp nwhookapi.cpp
  cl $(CFLAGS) /LD /Femstschook.dll mstschook.cpp nwhookapi.cpp $(LIBS)

test.exe: test.cpp nwhookapi.cpp
  cl $(CFLAGS) test.cpp nwhookapi.cpp $(LIBS)

clean:
  del /q *.obj
  del /q *.exe
  del /q *.dll
