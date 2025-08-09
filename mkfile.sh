CC=clang
CCX=clang++
cexe=bfint
cxx_exe=bfcom
llvmcfg=$(llvm-config --cxxflags --ldflags --system-libs --libs core)

$CC bfint.c -o $cexe
$CCX bfcom.cc -o bfcom $llvmcfg
