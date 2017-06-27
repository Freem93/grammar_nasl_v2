del lex.yy.cc
del parse_v2.exe

del y_tab.c

del y_tab.h
flex.exe lex.l

bison.exe -dy --verbose nasl_grammar.y

gcc lex.yy.c y_tab.c -o parse.exe
pause
parse.exe < plugins\mibiisa_overflow.nasl
pause
parse.exe < plugins\ms_sccm_detect.nasl
pause
parse.exe < plugins\openssl_AES_NI_padding_oracle.nasl
pause
parse.exe < plugins\openssl_ccs_1_0_1.nasl
pause
parse.exe < plugins\palo_alto_PAN-SA-2016-0012.nasl
pause
parse.exe < plugins\ping_host.nasl
pause
parse.exe < plugins\plone_authentication_bypass.nasl
pause
parse.exe < plugins\smb_nt_ms04-003.nasl
pause
parse.exe < plugins\snmp_dlink_user_pass_disclosure.nasl
pause
parse.exe < plugins\ssh_debian_find_weak_keys.nasl
pause
parse.exe < plugins\ssl3_tls1_iv_impl_info_disclosure.nasl
pause