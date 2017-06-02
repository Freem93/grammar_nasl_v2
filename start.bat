del lex.yy.cc
del parse.exe
del y_tab.c
del y_tab.h
flex.exe lex.l
bison.exe -dy --verbose nasl_grammar.y
gcc lex.yy.c y_tab.c -o parse.exe < example.nasl

parse.exe < example.nasl
pause
parse.exe < aaa.nasl
pause
parse.exe < test.nasl
pause
parse.exe < tests\signed.nasl
pause
parse.exe < tests\test_blowfish.nasl
pause
parse.exe < tests\test_bn.nasl
pause
parse.exe < tests\test_dh.nasl
pause
parse.exe < tests\test_dsa.nasl
pause
parse.exe < tests\test_hexstr.nasl
pause
parse.exe < tests\test_isotime.nasl
pause
parse.exe < tests\test_md.nasl
pause
parse.exe < tests\test_privkey.nasl
pause
parse.exe < tests\test_rsa.nasl
pause
parse.exe < tests\test_socket.nasl
pause
parse.exe < tests\testsuiteinit.nasl
pause
parse.exe < tests\testsuitesummary.nasl
pause
parse.exe < tests\test_script_signing.sh
pause
parse.exe < tests\README.txt
pause
parse.exe < tests\signed.nasl.asc
pause