# (C) Tenable Network Security, Inc.
#
# List of Suspicious files and information
#
# Includes functions used for testing the files.
#
# include('smb_func.inc');
# include('smb_hotfixes.inc');
# include('smb_hotfixes_fcheck.inc');
# include('smb_com_func.inc');
# include('misc_func.inc');
#
# suspicious_files.inc
# $Revision: 1.2 $
#

include('string.inc');

# Globals
Report = '';
Sys_root = '';

### Debug Flag ###
SF_VERBOSE_ERRORS = FALSE;

# Return Codes
# Negative values are conditions that should not occur at run-time
# Positive values can occur at run-time and should be handled
# gracefully.
SF_EMPTY_REPORT    = 1;   # The global report is empty.
SF_OK              = 0;   # Successful return.
SF_ERROR           = -1;  # General/Unknown/Upstream error.
SF_MISSING_ARG     = -2;  # Missing argument to function.
SF_UNEXPECTED_NULL = -3;  # Unexpected NULL value encountered.
SF_COM_FAIL        = -4;  # COM funcs fail to initialize.

# Error Templates
SF_ERROR_TEMPLATE = make_list(1, "%s(): Unknown or upstream error occurred.", SF_ERROR);
SF_MISSING_ARG_TEMPLATE = make_list(2, "%s(): missing required argument '%s'.", SF_MISSING_ARG);
SF_UNEXPECTED_NULL_TEMPLATE = make_list(2, "%s(): '%s' variable is unexpectedly NULL.", SF_UNEXPECTED_NULL);
SF_COM_FAIL_TEMPLATE = make_list(1, "%s(): com_init() failed to initalize.", SF_COM_FAIL);

_file_info['CoolWebSearch parasite variant']['aclui.dll'] = 'http://www.merijn.nu/programs.php#cwshredder';
_file_info['CoolWebSearch parasite variant']['localsplnet.dll'] = 'http://www.merijn.nu/programs.php#cwshredder';
_file_info['CoolWebSearch parasite variant']['madopew.dll'] = 'http://www.merijn.nu/programs.php#cwshredder';
_file_info['CoolWebSearch parasite variant']['mfplay.dll'] = 'http://www.merijn.nu/programs.php#cwshredder';
_file_info['CoolWebSearch parasite variant']['msdoh.dll'] = 'http://www.merijn.nu/programs.php#cwshredder';
_file_info['CoolWebSearch parasite variant']['rpcnt4.dll'] = 'http://www.merijn.nu/programs.php#cwshredder';
_file_info['hijacker']['msadblock32.dll'] = 'http://www.2-spyware.com/browser-hijackers-removal';
_file_info['NetNucleus/Mirar webband']['WinNB41.dll'] = 'http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb41/index.phtml';
_file_info['NetNucleus/Mirar webband']['WinNB42.dll'] = 'http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb42/index.phtml';
_file_info['RelatedLinks adware']['lbbho.dll'] = 'http://www.kephyr.com/spywarescanner/library/relatedlinks.lbbho/index.phtml';
_file_info['Trojan.Win32.StartPage.ky hijacker']['msie32.dll'] = '';

_reg_info[' BonziBuddy']['{A28C2A31-3AB0-4118-922F-F6B3184F5495}']['file'] = 'WebCompass.dll';
_reg_info[' BonziBuddy']['{A28C2A31-3AB0-4118-922F-F6B3184F5495}']['url'] = 'http://accs-net.com/smallfish/bonzi.htm';
_reg_info['0CAT YellowPages']['{D797AD6C-6447-4DB4-91D0-090344408E72}']['file'] = 'STIEbar.dll';
_reg_info['0CAT YellowPages']['{D797AD6C-6447-4DB4-91D0-090344408E72}']['url'] = 'http://www.sunbeltsecurity.com/threatdisplay.aspx?name=0cat.Yellowpages&tid=15162&cs=1750583A4AEE2AFA792C8ADA2FB06839';
_reg_info['180solutions']['{5DAFD089-24B1-4c5e-BD42-8CA72550717B}']['file'] = 'saiemod.dll';
_reg_info['180solutions']['{5DAFD089-24B1-4c5e-BD42-8CA72550717B}']['url'] = 'http://web.archive.org/web/20060510210005/http://www.surfassistant.com/eula.html';
_reg_info['2020Search']['{4E7BD74F-2B8D-469E-92C6-CE7EB590A94D}']['file'] = '2020Search2.dll';
_reg_info['2020Search']['{4E7BD74F-2B8D-469E-92C6-CE7EB590A94D}']['url'] = 'http://www.kephyr.com/spywarescanner/library/2020search/index.phtml';
_reg_info['321search.com search hijacker']['{7148369a-1105-4e85-83e0-085e784ba374}']['file'] = 'SearchAssistant.dll';
_reg_info['404Search']['{4E7BD74F-2B8D-469E-EEFD-ED6DB186CE4D}']['file'] = '404Search.dll';
_reg_info['404Search']['{53C330D6-A4AB-419B-B45D-FD4411C1FEF4}']['file'] = '404Search.dll';
_reg_info['7FaSSt /7Search']['{06DFEDAA-6196-11D5-BFC8-00508B4A487D}']['file'] = '7Search.dll';
_reg_info['aBetterinternet/Transponder']['{00000026-8735-428D-B81F-DD098223B25F}']['file'] = 'speer.dll';
_reg_info['aBetterinternet/Transponder']['{00000049-8F91-4D9C-9573-F016E7626484}']['file'] = 'ceres.dll';
_reg_info['ActiveSearch/411Ferret']['{12F02779-6D88-4958-8AD3-83C12D86ADC7}']['file'] = 'toolbar.dll';
_reg_info['Actual Names (AdvSearch) Internet Keywords']['{046D6EA4-15E3-4b27-8010-45BD78A9219E}']['file'] = 'inetkw.dll';
_reg_info['ActualNames SearchPike']['{92C7D65C-52F3-4545-8A35-213D730DB1ED}']['file'] = 'Spredirect.dll';
_reg_info['AdBars']['{51641EF3-8A7A-4D84-8659-B0911E947CC8}']['file'] = 'DownloadHtml.dll';
_reg_info['AdBlaster']['{2D7CB618-CC1C-4126-A7E3-F5B12D3BCF71}']['file'] = 'ngpw34.dll';
_reg_info['AdBlaster']['{2D7CB618-CC1C-4126-A7E3-F5B12D3BCF71}']['url'] = 'http://www.spyany.com/program/article_adw_rm_AdBlaster.html';
_reg_info['AdBlaster']['{E9147A0A-A866-4214-B47C-DA821891240F}']['file'] = 'ngsw31.dll';
_reg_info['AdBlaster']['{E9147A0A-A866-4214-B47C-DA821891240F}']['url'] = 'http://www.spyany.com/program/article_adw_rm_AdBlaster.html';
_reg_info['AdBlaster']['{941CA48C-3984-4E7D-AAF8-8755ED76EB50}']['file'] = 'dll';
_reg_info['AdBlaster']['{941CA48C-3984-4E7D-AAF8-8755ED76EB50}']['url'] = 'http://www.xblock.com/product_show.php?id=787';
_reg_info['AdBreak']['{00000000-D9E3-4BC6-A0BD-3D0CA4BE5271}']['file'] = 'Fhfmm.dll';
_reg_info['Adlogix InPop']['{024DE5EB-3649-445E-8D57-C09A9A33D479}']['file'] = 'phelper.dll';
_reg_info['Adlogix.com Zamingo adware']['{0B90AA1B-F649-44C3-9FD3-736C332CBBCF}']['file'] = 'IEEnhancer.dll';
_reg_info['Adlogix.com Zamingo adware']['{0B90AA1B-F649-44C3-9FD3-736C332CBBCF}']['url'] = 'http://www.spyany.com/program/article_adw_rm_Zamingo.html';
_reg_info['Adlogix.com Zamingo adware']['{5FA6752A-C4A0-4222-88C2-928AE5AB4966}']['file'] = 'SWin32.dll';
_reg_info['Adlogix.com Zamingo adware']['{5FA6752A-C4A0-4222-88C2-928AE5AB4966}']['url'] = 'http://www.spyany.com/program/article_adw_rm_Zamingo.html';
_reg_info['Adpowerzone.com keyword hijacker']['{7FC56022-4EDA-472E-8830-7CA92CCBD025}']['file'] = 'ServerSide.dll';
_reg_info['AdRoar']['{BDF6CE3D-F5C5-4462-9814-3C8EAC330CA8}']['file'] = 'AdRoar.dll';
_reg_info['AdRoar']['{E0F0E0E1-5D45-11D4-BC00-2DCC73302D70}']['file'] = 'cpr.dll';
_reg_info['AdRoar']['{FAC6E0E1-5D45-4907-BC00-302D702DCC73}']['file'] = 'cpr.dll';
_reg_info['AdsStore adware']['{00010a21-b924-4cd6-893c-eea1071ae8b3}']['file'] = 'PCDBS.DLL';
_reg_info['AdsStore adware']['{00010a21-b924-4cd6-893c-eea1071ae8b3}']['url'] = 'http://research.sunbelt-software.com/threatdisplay.aspx?name=AdsStore&threatid=1717';
_reg_info['Adtomi adware variant']['{A78860C8-EE1A-46DF-A97F-E3E6D433E80B}']['file'] = 'dll';
_reg_info['Advanced Searchbar']['{07531599-F255-4050-B96E-ECE5AA2E63A5}']['file'] = 'AdvancedBar.dll';
_reg_info['Adware DAE.A']['{81A99149-F047-4090-8AAD-D11FF4EFB734}']['file'] = 'dae.dll';
_reg_info['Adware DAE.A']['{81A99149-F047-4090-8AAD-D11FF4EFB734}']['url'] = 'http://www.trendmicro.com/vinfo/us/threat-encyclopedia/archive/malware/adw_dae.a';
_reg_info['Adware.Admess']['{9896231A-C487-43A5-8369-6EC9B0A96CC0}']['file'] = 'WStart.dll';
_reg_info['Adware.Admess']['{9896231A-C487-43A5-8369-6EC9B0A96CC0}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.admess.html';
_reg_info['Adware.Adtomi']['{B549456D-F5D0-4641-BCED-8648A0C13D83}']['file'] = 'BrowserHelper.dll';
_reg_info['Adware.Begin2Search']['{CB5B2BC6-F957-4D8A-BE67-83F3EC58BA01}']['file'] = 'dsktrf.dll';
_reg_info['Adware.Begin2Search']['{F0C08B30-BA30-4FEB-924B-2E250CF0697D}']['file'] = 'siq.dll';
_reg_info['Adware.DealHelper']['{D848A3CA-0BFB-4DE0-BA9E-A57F0CCA1C13}']['file'] = 'Dealhlpr.dll';
_reg_info['Adware.HungryHands']['{BCF96FB4-5F1B-497B-AECC-910304A55011}']['file'] = 'hh.dll';
_reg_info['Adware.IAGold']['{0A1A2A3A-4A5A-6A7A-8A9A-AABACADAEAFA}']['file'] = 'dll';
_reg_info['Adware.IEPageHelper']['{1C4DA27D-4D52-4465-A089-98E01BB725CA}']['file'] = 'inetdctr.dll';
_reg_info['Adware.IEPageHelper']['{A6F42CAD-2559-48DF-AF30-89E480AF5DFA}']['file'] = 'Bho.dll';
_reg_info['Adware.IEPageHelper']['{D8E25C53-9508-4f5c-9249-D98D438891D5}']['file'] = 'inetdctr.dll';
_reg_info['Adware.IESP.mht/CasinoPalazzo foistware']['{A3DFDA85-1D92-4E28-8C0C-522574ACDC8A}']['file'] = 'msacrohlp.dll';
_reg_info['Adware.LizardBar']['{029BB53A-C312-4b09-9B4F-ED57AF027B28}']['file'] = 'winhlp32.dll';
_reg_info['Adware.Magicads']['{F760CB9E-C60F-4A89-890E-FAE8B849493E}']['file'] = 'Madise.dll';
_reg_info['Adware.Margoc variant']['{57CD6D2E-0291-488F-B846-AF101B367DD5}']['file'] = 'dll';
_reg_info['Adware.Margoc variant']['{81D66134-ADC3-4C6D-B0A9-03D4EE35B849}']['file'] = 'dll';
_reg_info['Adware.Margoc variant']['{FA040B34-FBE9-4BEF-9D85-F90BECAACA99}']['file'] = 'dll';
_reg_info['Adware.Margoc']['{D537A3D0-8C07-4D62-953F-162207F5090D}']['file'] = 'regsvrac32.dll';
_reg_info['Adware.Margoc']['{D537A3D0-8C07-4D62-953F-162207F5090D}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.margoc.html';
_reg_info['Adware.MultiClicker']['{FD3A6AB4-5527-4B52-90AF-F90CD3270861}']['file'] = 'inetconnect.dll';
_reg_info['Adware.OpenSite']['{30A56549-9D5B-4D34-AFA7-440A7F0538A9}']['file'] = 'Opnste.dll';
_reg_info['Adware.Ramdud']['{00000015-A527-34E7-25C2-03A4E313B2E9}']['file'] = 'winsrvs_1.dll';
_reg_info['Adware.Sa']['{4BCF322B-9621-4e90-9678-F1424EB7584E}']['file'] = 'Udpmod.dll';
_reg_info['Adware.Sa']['{7B55BB05-0B4D-44fd-81A6-B136188F5DEB}']['file'] = 'questmod.dll';
_reg_info['Adware.Slagent']['{008DB894-99ED-445D-8547-0E7C9808898D}']['file'] = '4b_1,0,1,2_mslagent.dll';
_reg_info['Adware.Slagent']['{008DB894-99ED-445D-8547-0E7C9808898D}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.simcss.b.html';
_reg_info['Adware.Slagent']['{021BB032-80A8-4FB6-B3D5-CF27B1553B95}']['file'] = '4b_1,0,1,0_mslagent.dll';
_reg_info['Adware.Slagent']['{021BB032-80A8-4FB6-B3D5-CF27B1553B95}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.simcss.b.html';
_reg_info['Adware.Slagent']['{ACB3E0B7-7D0C-40B7-99B3-3EEACDF86BFB}']['file'] = '4b_1,0,1,1_mslagent.dll';
_reg_info['Adware.Slagent']['{ACB3E0B7-7D0C-40B7-99B3-3EEACDF86BFB}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.simcss.b.html';
_reg_info['Adware.Syslibie']['{F195A1A9-4033-4E5B-B85C-848C3E31A83A}']['file'] = 'syslibie.dll';
_reg_info['Adware.WinFavorites']['{9C691A33-7DDA-4C2F-BE4C-C176083F35CF}']['file'] = 'bridge.dll';
_reg_info['Adware.WinFavorites']['{9C691A33-7DDA-4C2F-BE4C-C176083F35CF}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.winfavorites.html';
_reg_info['AdwareSpy']['{FCADDC14-BD46-408A-9842-CDBE1C6D37EB}']['file'] = 'Adwarespy.dll';
_reg_info['AdwareSpy']['{FCADDC14-BD46-408A-9842-CDBE1C6D37EB}']['url'] = 'http://www.softwaretipsandtricks.com/browser_helper_objects/696-browserhelpere******dll%20%28*%20%20random%20digit%29,%20Ms***.html';
_reg_info['Alexa Toolbar']['{6AF9BC61-3CC5-42A7-82D1-FFC2562A7289}']['file'] = 'Alxie328.dll';
_reg_info['Alexa Toolbar']['{D1F6ABEF-B889-11D2-8E3C-DCCA155F9A71}']['file'] = 'Alexaie.dll';
_reg_info['Alexa']['{3DF73DF8-41E2-4fc2-8CBF-4B9407433755}']['file'] = 'lxTB.dll';
_reg_info['Alexa']['{3DF73DF8-41E2-4fc2-8CBF-4B9407433755}']['url'] = 'http://web.archive.org/web/20031003051654/http://www.safersite.com/PestInfo/a/Alexa_Toolbar.asp';
_reg_info['Alexa']['{F1FABE79-25FC-46de-8C5A-2C6DB9D64333}']['file'] = 'AlxTB1.dll';
_reg_info['Alexa']['{F1FABE79-25FC-46de-8C5A-2C6DB9D64333}']['url'] = 'http://web.archive.org/web/20031003051654/http://www.safersite.com/PestInfo/a/Alexa_Toolbar.asp';
_reg_info['AlibabaIEToolBar']['{850B69E4-90DB-4F45-8621-891BF35A5B53}']['file'] = 'bar.dll';
_reg_info['Apropos Adware']['{016235BE-59D4-4CEB-ADD5-E2378282A1D9}']['file'] = 'CxtPls.dll';
_reg_info['Apropos Adware']['{016235BE-59D4-4CEB-ADD5-E2378282A1D9}']['url'] = 'http://vil.nai.com/vil/content/v_101223.htm';
_reg_info['AtHoc Toolbar']['{001F2470-5DF5-11d3-B991-00A0C9BB0874}']['file'] = 'AtHocTBr.DLL';
_reg_info['AtHoc Toolbar']['{001F2470-5DF5-11d3-B991-00A0C9BB0874}']['url'] = 'http://xforce.iss.net/xforce/xfdb/17628';
_reg_info['Aureate/Radiate']['{EBBFE27C-BDF0-11D2-BBE5-00609419F467}']['file'] = 'amcis.dll';
_reg_info['Aureate/Radiate']['{EBBFE27C-BDF0-11D2-BBE5-00609419F467}']['url'] = 'http://www.cexx.org/aureate.htm';
_reg_info['AutoSearch']['{00000000-0000-0000-0000-000000000001}']['file'] = 'safesearch.dll';
_reg_info['BackDoor Lixy']['{1E1B2879-88FF-11D2-8D96-D7ACAC95951A}']['file'] = 'Lid.dll';
_reg_info['BackDoor Lixy']['{1E1B2879-88FF-11D2-8D96-D7ACAC95951A}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/backdoor.lixy.html';
_reg_info['Backdoor.Berbew.P']['{7EFFAAFF-EA0A-1A3A-CBCD-F13522D53649}']['file'] = 'dll';
_reg_info['Backdoor.Berbew.P']['{7EFFAAFF-EA0A-1A3A-CBCD-F13522D53649}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/backdoor.berbew.p.html';
_reg_info['Backdoor.Lixy.B']['{1E1B2879-88FF-11D2-8D96-000000000003}']['file'] = 'SSocks5.dll';
_reg_info['Backdoor.Lixy.B']['{1E1B2879-88FF-11D2-8D96-000000000004}']['file'] = 'Ssocks32.dll';
_reg_info['BaiDu toolbar']['{B580CF65-E151-49C3-B73F-70B13FCA8E86}']['file'] = 'BaiDuBar.dll';
_reg_info['BandObjects/eStart']['{8786386E-4B22-11D6-9C60-E5DA06D87378}']['file'] = 'BandObjs1,0,0,1.dll';
_reg_info['Bargain Buddy']['{CE31A1F7-3D90-4874-8FBE-A5D97F8BC8F1}']['file'] = 'Apuc.dll';
_reg_info['BDPLugin']['{BC207F7D-3E63-4ACA-99B5-FB5F8428200C}']['file'] = 'Bdsrhook.dll';
_reg_info['BDPLugin']['{BC207F7D-3E63-4ACA-99B5-FB5F8428200C}']['url'] = 'http://www.spyany.com/program/article_adw_rm_BDHelper.html';
_reg_info['Begin2Search bar, iLookup variant']['{4D568F0F-8AC9-40AB-88B7-415134C78777}']['file'] = 'dll';
_reg_info['Best Phrases adware']['{E8B4F3AA-9509-4081-9A85-914D5E9BEC81}']['file'] = 'bpv1a.dll';
_reg_info['Best Phrases adware']['{E8B4F3AA-9509-4081-9A85-914D5E9BEC81}']['url'] = 'http://www.spyany.com/program/article_adw_rm_Best_Phrases.html';
_reg_info['BestPhrases variant']['{F4A645D0-D4D5-439E-9DBC-B31BBD9CB890}']['file'] = 'BPV2s.dll';
_reg_info['Blazefind IESearchbar']['{71ED4FBA-4024-4bbe-91DC-9704C93F453E}']['file'] = 'Iesearchbar.dll';
_reg_info['Blazefind IESearchbar']['{71ED4FBA-4024-4bbe-91DC-9704C93F453E}']['url'] = 'http://www.kephyr.com/spywarescanner/library/iesearchbar/index.phtml';
_reg_info['BlazeFind Websearch']['{83DE62E0-5805-11D8-9B25-00E04C60FAF2}']['file'] = '2_0_1browserhelper2.dll';
_reg_info['BlazeFind Websearch']['{83DE62E0-5805-11D8-9B25-00E04C60FAF2}']['url'] = 'http://www.spywareguide.com/product_show.php?id=724';
_reg_info['BlazeFind Websearch']['{C5941EE5-6DFA-11D8-86B0-0002441A9695}']['file'] = '3_0_1browserhelper3.dll';
_reg_info['BlazeFind Websearch']['{C5941EE5-6DFA-11D8-86B0-0002441A9695}']['url'] = 'http://www.spywareguide.com/product_show.php?id=724';
_reg_info['BlazeFind Websearch']['{FBED6A02-71FB-11D8-86B0-0002441A9695}']['file'] = '5_0_1browserhelper5.dll';
_reg_info['BlazeFind Websearch']['{FBED6A02-71FB-11D8-86B0-0002441A9695}']['url'] = 'http://www.spywareguide.com/product_show.php?id=724';
_reg_info['BlazeFind/SearchRelevancy hijacker']['{1D7E3B41-23CE-469B-BE1B-A64B877923E1}']['file'] = 'SearchRelevancy.dll';
_reg_info['BookedSpace variant']['{0019C3E2-DD48-4A6D-ABCD-8D32436313D9}']['file'] = 'bxsx5.dll';
_reg_info['BookedSpace variant']['{0019C3E2-DD48-4A6D-ABCD-8D32436323D9}']['file'] = 'bxxs5.dll';
_reg_info['BookedSpace/Remanent']['{2B3452C5-1B9A-440F-A203-F6ED0F64C895}']['file'] = 'rem00001.dll';
_reg_info['BookedSpace']['{0019C3E2-DD48-4A6D-AB2D-8D32436313D9}']['file'] = 'oo4.dll';
_reg_info['BookedSpace']['{392BE62B-E7DE-430A-8859-0AFE677DE6E1}']['file'] = 'bs2.dll';
_reg_info['BookedSpace']['{A85C4A1B-BD36-44E5-A70F-8EC347D9B24F}']['file'] = 'bs3.dll';
_reg_info['BookedSpace']['{A85C4A1B-BD36-44E5-A70F-8EC347D9B24F}']['url'] = 'http://www.symantec.com/security_response/writeup.jsp?docid=2003-101514-2307-99';
_reg_info['BrowserAid CashToolbar/QuickLaunch toolbar']['{5F5564AC-DE7A-4DCD-9296-32E71A35DCB6}']['file'] = 'Browseraidtoolbar.dll';
_reg_info['BrowserAid/ABCSearch']['{6D55490C-1BD4-4790-BA31-84D261316E28}']['file'] = 'Highlighthelper.dll';
_reg_info['BrowserAid/FeaturedResults']['{0DDBB570-0396-44C9-986A-8F6F61A51C2F}']['file'] = 'Msiefr40.dll';
_reg_info['BrowserAid/Rundll16']['{80672997-D58C-4190-9843-C6C61AF8FE97}']['file'] = 'rundll16.dll';
_reg_info['BrowserAid/SearchandClick']['{087173EF-9829-4F49-8340-A524177D3F60}']['file'] = 'inetp60.dll';
_reg_info['BrowserAid/SearchandClick']['{087173EF-9829-4F49-8340-A524177D3F60}']['url'] = 'http://www.kephyr.com/spywarescanner/library/browseraid/index.phtml';
_reg_info['BrowserAid/Startium variant']['{12EE7A5E-0674-42f9-A76A-000000004D00}']['file'] = 'stlb2.dll';
_reg_info['BrowserAid/Startium variant']['{778C2A73-4707-41d1-9269-03FF7DE5FFB8}']['file'] = 'D3D869D4.dll';
_reg_info['BrowserAid/Startium']['{2CF0B992-5EEB-4143-99C0-5297EF71F443}']['file'] = 'stlbdist.dll';
_reg_info['BrowserAid/Startium']['{2CF0B992-5EEB-4143-99C0-5297EF71F444}']['file'] = 'stlbdist.dll';
_reg_info['BrowserAid/Startium']['{2CF0B992-5EEB-4143-99C0-5297EF71F44A}']['file'] = 'stlbad123.dll';
_reg_info['BrowserAid/Startium']['{2CF0B992-5EEB-4143-99C2-5297EF71F44A}']['file'] = 'stlbad123.dll';
_reg_info['BrowserPal toolbar']['{5F5564AC-DE7A-4DCD-9296-32E71A35DCB7}']['file'] = 'bptlb.dll';
_reg_info['BrowserPal Toolbar']['{D34F641F-5210-4EB0-8ED5-9179F47E15B7}']['file'] = 'blckbho.dll';
_reg_info['Browserplugin.com malware']['{1BDD55B8-3985-4E59-B906-5E0AD56D6710}']['file'] = 'WH';
_reg_info['BrowserVillage Toolbar']['{4E7BD74F-2B8D-469E-D7F9-FE60B89CAC3F}']['file'] = 'bvillage.dll';
_reg_info['BrowserVillage Toolbar']['{4E7BD74F-2B8D-469E-D7F9-FE60B89CAC3F}']['url'] = 'http://www.nuker.com/container/details/browservillage_toolbar.php';
_reg_info['Burnaby Module >e-card_viewer']['{3750BFA3-1392-4AF3-AF86-9D2D4776E5A4}']['file'] = 'potd.dll';
_reg_info['CashSaver spyware']['{B9ADBF45-B136-4FC5-8582-48C2A22600CE}']['file'] = 'cashsaverbho.dll';
_reg_info['CasinoRewards software']['{FF905E0C-CFE9-4A90-AFFF-C13AF5D908F0}']['file'] = 'CasinoRewardsExplorerToolbar.dll';
_reg_info['CheckUrl']['{A9EEF0D7-5695-45BA-8943-ED3B95A50BD2}']['file'] = 'CheckUrl.dll';
_reg_info['CheckUrl']['{A9EEF0D7-5695-45BA-8943-ED3B95A50BD2}']['url'] = 'http://web.archive.org/web/20061110002645/http://www.pestpatrol.com/spywarecenter/pest.aspx?id=453078193';
_reg_info['ClearSearch']['{00000000-0000-0000-0000-000000000221}']['file'] = 'CSIE.DLL';
_reg_info['ClearSearch']['{00000000-0000-0000-0000-000000000240}']['file'] = 'IE_ClrSch.dll';
_reg_info['ClearSearch']['{00000000-0000-0000-0000-000000002230}']['file'] = 'Csbb.dll';
_reg_info['ClearSearch']['{947E6D5A-4B9F-4CF4-91B3-562CA8D03313}']['file'] = 'IE_ClrSch.dll';
_reg_info['ClearStream Accelerator']['{83DC91DB-7896-43E3-B34D-A7D043F16BB1}']['file'] = 'rdsa.dll';
_reg_info['ClearStream Accelerator']['{83DC91DB-7896-43E3-B34D-A7D043F16BB1}']['url'] = 'http://www.spyany.com/program/article_spw_rm_ClearStream_Accelerator.html';
_reg_info['ClearStream Accelerator']['{AC109D01-32D6-4EB5-8300-D3C5EBAC7C83}']['file'] = 'X2ff.dll';
_reg_info['ClearStream Accelerator']['{AC109D01-32D6-4EB5-8300-D3C5EBAC7C83}']['url'] = 'http://www.spyany.com/program/article_spw_rm_ClearStream_Accelerator.html';
_reg_info['ClearStream Accelerator']['{D319662B-D5BF-4538-ADF3-8D3E36362608}']['file'] = 'x0ff.dll';
_reg_info['ClearStream Accelerator']['{D319662B-D5BF-4538-ADF3-8D3E36362608}']['url'] = 'http://www.spyany.com/program/article_spw_rm_ClearStream_Accelerator.html';
_reg_info['Clickspring/PurityScan']['{1B7D753B-1981-4bd2-91F3-6D055EE113A0}']['file'] = 'NDrv.dll';
_reg_info['Clickspring/PurityScan']['{A78CC2FF-6E4E-4556-B27C-D7C3A70D7A50}']['file'] = 'NDrv.dll';
_reg_info['ClientMan']['{00A0A40C-F432-4C59-BA11-B25D142C7AB7}']['file'] = '2IN';
_reg_info['ClientMan']['{0982868C-47F0-4EFB-A664-C7B0B1015808}']['file'] = 'Newads~1.dll';
_reg_info['ClientMan']['{0BA1C6EB-D062-4E37-9DB5-B07743276324}']['file'] = 'ms****.dll';
_reg_info['ClientMan']['{166348F1-2C41-4C9F-86BB-EB2B8ADE030C}']['file'] = 'msvrfy';
_reg_info['ClientMan']['{25F7FA20-3FC3-11D7-B487-00D05990014C}']['file'] = 'ms';
_reg_info['ClientMan']['{447160CD-ECF5-4EA2-8A8A-1F70CA363F85}']['file'] = 'bundle';
_reg_info['ClientMan']['{5ED50735-B0D9-47C6-9774-02DD8E6FE053}']['file'] = 'disable.dll';
_reg_info['ClientMan']['{94927A13-4AAA-476A-989D-392456427688}']['file'] = 'urlcli';
_reg_info['ClientMan']['{96BE1D9A-9E54-4344-A27A-37C088D64FB4}']['file'] = 'dnsrep';
_reg_info['ClientMan']['{96BE1D9A-9E54-4344-A27A-37C088D64FB4}']['file'] = 'mseffm.dll';
_reg_info['ClientMan']['{A097840A-61F8-4B89-8693-F68F641CC838}']['file'] = 'urlcli';
_reg_info['ClientMan']['{ba77911b-a393-4a2e-b5b5-5b8ed17d7b43}']['file'] = 'disable1.dll';
_reg_info['ClientMan']['{CC916B4B-BE44-4026-A19D-8C74BBD23361}']['file'] = 'Gstyle~1.dll';
_reg_info['ClientMan']['{FCADDC14-BD46-408A-9842-CDBE1C6D37EB}']['file'] = 'browserhelpere';
_reg_info['Clitor']['{1E1B2879-88FF-11D2-8D96-123457123457}']['file'] = 'Explorer.dll';
_reg_info['CnsMin related']['{E5E4E352-6947-44EE-A420-DB84EFD3FE93}']['file'] = 'ehelper.dll';
_reg_info['CnsMin variant']['{CA92B524-BC8A-4610-BD2C-6BD3E28155D0}']['file'] = 'Bdhelper.dll';
_reg_info['CnsMin']['{118CE65F-5D86-4AEA-A9BD-94F92B89119F}']['file'] = 'CnsMinIdn.dll';
_reg_info['CnsMin']['{1B0E7716-898E-48cc-9690-4E338E8DE1D3}']['file'] = 'Assist.dll';
_reg_info['CnsMin']['{6231D512-E4A4-4DF2-BE62-5B8F0EE348EF}']['file'] = 'cesweb.dll';
_reg_info['CnsMin']['{D157330A-9EF3-49F8-9A67-4141AC41ADD4}']['file'] = 'CnsHook.dll';
_reg_info['Comet Cursor']['{1678F7E1-C422-11D0-AD7D-00400515CAAA}']['file'] = 'comet.dll';
_reg_info['Comet Cursor']['{6D0AC7F7-B628-4581-A8B2-14D97F24AA76}']['file'] = 'brbho.dll';
_reg_info['Comet Cursor']['{6D0AC7F7-B628-4581-A8B2-14D97F24AA76}']['url'] = 'http://www.symantec.com/security_response/writeup.jsp?docid=2004-091615-0103-99';
_reg_info['Comet Cursor']['{96DA5BEE-4ACC-476C-B3EC-54C6730C4293}']['file'] = 'brbho.dll';
_reg_info['Comet Cursor']['{D14D6793-9B65-11D3-80B6-00500487BDBA}']['file'] = 'Csbho.dll';
_reg_info['Commander toolbar']['{29F7B7FA-ADC8-48ea-9E1C-EA87A05AE642}']['file'] = 'sbb.dll';
_reg_info['Commander Toolbar']['{6596829B-37D4-40ad-971B-1E9041725C52}']['file'] = 'ietb.dll';
_reg_info['Commonname toolbar']['{00000000-0000-0000-0000-000000000000}']['file'] = 'CnbarIE.dll';
_reg_info['Commonname toolbar']['{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}']['file'] = 'CnbarIE.dll';
_reg_info['Commonname toolbar']['{6656B666-992F-4D74-8588-8CAC9E79D90C}']['file'] = 'CNBabe.dll';
_reg_info['Commonname toolbar']['{A6475E6B-3C2E-4B1F-82FD-8F1C0B1D8AD0}']['file'] = 'BabeIE.dll';
_reg_info['Comodo Trust Toolbar']['{D80E1356-AC78-4218-961C-A7689B4CB7FE}']['file'] = 'Ttbbho.dll';
_reg_info['Comodo Trust Toolbar']['{D80E1356-AC78-4218-961C-A7689B4CB7FE}']['url'] = 'http://www.trusttoolbar.com/';
_reg_info['CoolWebSearch parasite variant']['{00000000-0000-0000-0000-000000000000}']['file'] = 'msxmlpp.dll';
_reg_info['CoolWebSearch parasite variant']['{00000000-0000-0000-0000-000000000000}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{00000000-0000-0000-0000-000000000001}']['file'] = 'msxmlfilt.dll';
_reg_info['CoolWebSearch parasite variant']['{00000000-0000-0000-0000-000000000001}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{00110011-4B0B-44D5-9718-90C88817369B}']['file'] = 'NavExt.dll';
_reg_info['CoolWebSearch parasite variant']['{00110011-4B0B-44D5-9718-90C88817369B}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{086AE192-23A6-48D6-96EC-715F53797E85}']['file'] = 'DReplace.dll';
_reg_info['CoolWebSearch parasite variant']['{086AE192-23A6-48D6-96EC-715F53797E85}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{0B519E07-7824-4adc-8890-93D5EABBF285}']['file'] = 'msadocm32.dll';
_reg_info['CoolWebSearch parasite variant']['{0B519E07-7824-4adc-8890-93D5EABBF285}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{12D02C08-218F-4A11-BDE1-6611ADB7B81F}']['file'] = 'sys32_app.dll';
_reg_info['CoolWebSearch parasite variant']['{12D02C08-218F-4A11-BDE1-6611ADB7B81F}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{150FA160-130D-451F-B863-B655061432BA}']['file'] = 'mgs_32.dll';
_reg_info['CoolWebSearch parasite variant']['{150FA160-130D-451F-B863-B655061432BA}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{17DA0C9E-4A27-4ac5-BB75-5D24B8CDB972}']['file'] = 'Excel10.dll';
_reg_info['CoolWebSearch parasite variant']['{17DA0C9E-4A27-4ac5-BB75-5D24B8CDB972}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFB1}']['file'] = 'MS';
_reg_info['CoolWebSearch parasite variant']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFB1}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFB2}']['file'] = 'MS';
_reg_info['CoolWebSearch parasite variant']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFB2}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{275636E4-A535-4668-9FF1-86DC0C62D446}']['file'] = 'msopt.dll';
_reg_info['CoolWebSearch parasite variant']['{275636E4-A535-4668-9FF1-86DC0C62D446}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{2D38A51A-23C9-48a1-A33C-48675AA2B494}']['file'] = 'winres.dll';
_reg_info['CoolWebSearch parasite variant']['{2D38A51A-23C9-48a1-A33C-48675AA2B494}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{30192F8D-0958-44E6-B54D-331FD39AC959}']['file'] = 'toolband.dll';
_reg_info['CoolWebSearch parasite variant']['{30192F8D-0958-44E6-B54D-331FD39AC959}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{441354C5-911B-409B-9A66-A11D6D4E1A22}']['file'] = 'sdmtb.dll';
_reg_info['CoolWebSearch parasite variant']['{441354C5-911B-409B-9A66-A11D6D4E1A22}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{467FAEB2-5F5B-4c81-BAE0-2A4752CA7F4E}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{467FAEB2-5F5B-4c81-BAE0-2A4752CA7F4E}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{4C1B116F-2860-46db-8E6C-B4BFC4DFD683}']['file'] = 'ietlbass32.dll';
_reg_info['CoolWebSearch parasite variant']['{4C1B116F-2860-46db-8E6C-B4BFC4DFD683}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{52DC9EC1-35A9-4914-98D9-D568A9854DA2}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{52DC9EC1-35A9-4914-98D9-D568A9854DA2}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{5321E378-FFAD-4999-8C62-03CA8155F0B3}']['file'] = '1.00.07.dll';
_reg_info['CoolWebSearch parasite variant']['{5321E378-FFAD-4999-8C62-03CA8155F0B3}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{5483427F-93B8-1470-5A89-E6B56484CDB2}']['file'] = '';
_reg_info['CoolWebSearch parasite variant']['{5483427F-93B8-1470-5A89-E6B56484CDB2}']['file'] = '';
_reg_info['CoolWebSearch parasite variant']['{5483427F-93B8-1470-5A89-E6B56484CDB2}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{5742F79A-1D91-42c4-990C-B46CF55A6478}']['file'] = 'setfgi.dll';
_reg_info['CoolWebSearch parasite variant']['{5742F79A-1D91-42c4-990C-B46CF55A6478}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{587DBF2D-9145-4c9e-92C2-1F953DA73773}']['file'] = 'Iefeatsl.dll';
_reg_info['CoolWebSearch parasite variant']['{587DBF2D-9145-4c9e-92C2-1F953DA73773}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{62160EEF-9D84-4C19-B7B8-6AC2526CD726}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{62160EEF-9D84-4C19-B7B8-6AC2526CD726}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{6CC1C91A-AE8B-4373-A5B4-28BA1851E39A}']['file'] = 'winlink.dll';
_reg_info['CoolWebSearch parasite variant']['{6CC1C91A-AE8B-4373-A5B4-28BA1851E39A}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{710089CF-87C3-763F-C8F6-5A0DBFD3AEC3}']['file'] = 'Multiple file names';
_reg_info['CoolWebSearch parasite variant']['{710089CF-87C3-763F-C8F6-5A0DBFD3AEC3}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{75A46C7E-D7AB-55F3-8DF2-D9A7FFD913E6}']['file'] = 'Multiple file names';
_reg_info['CoolWebSearch parasite variant']['{75A46C7E-D7AB-55F3-8DF2-D9A7FFD913E6}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{79369D5C-2903-4b7a-ADE2-D5E0DEE14D24}']['file'] = 'GoogleMS.dll';
_reg_info['CoolWebSearch parasite variant']['{79369D5C-2903-4b7a-ADE2-D5E0DEE14D24}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{799A370D-5993-4887-9DF7-0A4756A77D00}']['file'] = 'search.dll';
_reg_info['CoolWebSearch parasite variant']['{799A370D-5993-4887-9DF7-0A4756A77D00}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{7FE49EAE-AA38-4044-9D10-09DAB477051F}']['file'] = 'popup_bl.dll';
_reg_info['CoolWebSearch parasite variant']['{7FE49EAE-AA38-4044-9D10-09DAB477051F}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{82E8FF5B-20DA-4F43-9787-09FA534B7627}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{82E8FF5B-20DA-4F43-9787-09FA534B7627}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{834261E1-DD97-4177-853B-C907E5D5BD6E}']['file'] = 'dpe.dll';
_reg_info['CoolWebSearch parasite variant']['{834261E1-DD97-4177-853B-C907E5D5BD6E}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{85CBFDE0-B26B-4EE5-BD3C-4DE111DE763E}']['file'] = 'Winnet.dll';
_reg_info['CoolWebSearch parasite variant']['{85CBFDE0-B26B-4EE5-BD3C-4DE111DE763E}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{98DBBF16-CA43-4c33-BE80-99E6694468A4}']['file'] = 'msole.dll';
_reg_info['CoolWebSearch parasite variant']['{98DBBF16-CA43-4c33-BE80-99E6694468A4}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{99D764FC-CDD7-00B8-618D-0880E43E5DFC}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{99D764FC-CDD7-00B8-618D-0880E43E5DFC}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{A2833482-B023-4C65-B09D-EE47A4E8CC56}']['file'] = 'botnet1.dll';
_reg_info['CoolWebSearch parasite variant']['{A2833482-B023-4C65-B09D-EE47A4E8CC56}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{A5366673-E8CA-11D3-9CD9-0090271D075B}']['file'] = 'msacmx.dll';
_reg_info['CoolWebSearch parasite variant']['{A5366673-E8CA-11D3-9CD9-0090271D075B}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{A55581DC-2CDB-4089-8878-71A080B22342}']['file'] = 'Autosearch.dll';
_reg_info['CoolWebSearch parasite variant']['{A55581DC-2CDB-4089-8878-71A080B22342}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{A5E0B170-04FA-11d1-B7DA-00A0C90348D6}']['file'] = 'msdocvw.dll';
_reg_info['CoolWebSearch parasite variant']['{A5E0B170-04FA-11d1-B7DA-00A0C90348D6}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{A903BF95-883E-4E70-AEC8-6C27CDC0A6B2}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{A903BF95-883E-4E70-AEC8-6C27CDC0A6B2}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{A9A674BF-771F-42E5-A440-D20DDA85A862}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{A9A674BF-771F-42E5-A440-D20DDA85A862}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{B847676D-72AC-4393-BFFF-43A1EB979352}']['file'] = 'wcadw.dll';
_reg_info['CoolWebSearch parasite variant']['{B847676D-72AC-4393-BFFF-43A1EB979352}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{B957F25D-F812-44c4-A23C-249CCFE0AAE0}']['file'] = 'msnet.dll';
_reg_info['CoolWebSearch parasite variant']['{B957F25D-F812-44c4-A23C-249CCFE0AAE0}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{B9D90B27-AD4A-413a-88CB-3E6DDC10DC2D}']['file'] = 'MSOPT.DLL';
_reg_info['CoolWebSearch parasite variant']['{B9D90B27-AD4A-413a-88CB-3E6DDC10DC2D}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{CBEFB350-ED5B-4115-B846-C1041676B377}']['file'] = 'CustomIE.dll';
_reg_info['CoolWebSearch parasite variant']['{CBEFB350-ED5B-4115-B846-C1041676B377}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{CBEFB350-ED5B-4115-B846-C1041676B388}']['file'] = 'CustIE32.dll';
_reg_info['CoolWebSearch parasite variant']['{CBEFB350-ED5B-4115-B846-C1041676B388}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{CF021F40-3E14-23A5-CBA2-71766C641306}']['file'] = 'vld1306.dll';
_reg_info['CoolWebSearch parasite variant']['{CF021F40-3E14-23A5-CBA2-71766C641306}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{D34F08C5-4F18-477c-86CB-1A9BEECFE37B}']['file'] = 'dll';
_reg_info['CoolWebSearch parasite variant']['{D34F08C5-4F18-477c-86CB-1A9BEECFE37B}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{E2DDF680-9905-4dee-8C64-0A5DE7FE133C}']['file'] = 'mssearch.dll';
_reg_info['CoolWebSearch parasite variant']['{E2DDF680-9905-4dee-8C64-0A5DE7FE133C}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{E7AFFF2A-1B57-49C7-BF6B-E5123394C970}']['file'] = 'webinfo.dll';
_reg_info['CoolWebSearch parasite variant']['{E7AFFF2A-1B57-49C7-BF6B-E5123394C970}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{EB23F789-F17F-4bcc-988B-6B70A3A67E9C}']['file'] = 'Zero-Popup.dll';
_reg_info['CoolWebSearch parasite variant']['{EB23F789-F17F-4bcc-988B-6B70A3A67E9C}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{FC2593E3-3E5A-410F-AF3D-82613CCE58E5}']['file'] = 'sr.dll';
_reg_info['CoolWebSearch parasite variant']['{FC2593E3-3E5A-410F-AF3D-82613CCE58E5}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{FD9BC004-8331-4457-B830-4759FF704C22}']['file'] = 'Msiesh.dll';
_reg_info['CoolWebSearch parasite variant']['{FD9BC004-8331-4457-B830-4759FF704C22}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CoolWebSearch parasite variant']['{FF1BF4C7-4E08-4A28-A43F-9D60A9F7A880}']['file'] = 'Mshelper.dll';
_reg_info['CoolWebSearch parasite variant']['{FF1BF4C7-4E08-4A28-A43F-9D60A9F7A880}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['CooolWebSearch parasite variant']['{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}']['file'] = 'DNSErr.dll';
_reg_info['CooolWebSearch parasite variant']['{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['Coulomb dialer related parasite']['{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE50}']['file'] = 'saristar.dll';
_reg_info['CSApp']['{CD209A08-98B5-4669-AF9F-447AC5253356}']['file'] = 'CSapp.dll';
_reg_info['Csearch']['{D8FA0364-7866-40A7-B340-A6069265AD9F}']['file'] = 'Csearch.dll';
_reg_info['Csearch']['{D8FA0364-7866-40A7-B340-A6069265AD9F}']['url'] = 'http://www.symantec.com/security_response/writeup.jsp?docid=2005-041417-1708-99';
_reg_info['CustomToolbar']['{21301D69-B8F1-46AA-B0B5-09EE2285914C}']['file'] = 'CustomToolbar.dll';
_reg_info['DailyWinner Prize Bar']['{7DD896A9-7AEB-430F-955B-CD125604FDCB}']['file'] = 'Veg32.dll';
_reg_info['Deltabar : Deltaclick']['{0FC817C2-3B45-11D4-8340-0050DA825906}']['file'] = 'DeltaClick.dll';
_reg_info['Deltabar : Deltaclick']['{0FC817C2-3B45-11D4-8340-0050DA825906}']['url'] = 'https://support.microsoft.com/en-us/kb/316770';
_reg_info['DigitalNames spyware related']['{531553EB-B210-4116-BC2C-C09608F4193E}']['file'] = 'SetGlbHO.dll';
_reg_info['DigitalNames spyware related']['{531553EB-B210-4116-BC2C-C09608F4193E}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/spyware.digitalnames.html';
_reg_info['Divago Surfairy']['{BB9AAAF3-4F8D-48B5-A565-FF3E58433DC2}']['file'] = 'SurfairyHlp.dll';
_reg_info['Divago Surfairy']['{E0B9B5FE-B66E-4FB0-A1D9-726F0E743CFD}']['file'] = 'SurfairyPP.dll';
_reg_info['DyFuCa/Internet Optimizer']['{00000010-6F7D-442C-93E3-4A4827C2E4C8}']['file'] = 'nem219.dll';
_reg_info['Dyfuca/Internet Optimizer']['{432D8C41-8586-11D8-997D-00C026232EB9}']['file'] = 'bvm202.dll';
_reg_info['Dyfuca/Internet Optimizer']['{F7F808F0-6F7D-442C-93E3-4A4827C2E4C8}']['file'] = 'opti130.dll';
_reg_info['Dynamic Desktop Media adware variant']['{9819C369-5F62-4D37-9A42-44043A742C1E}']['file'] = 'redirect.dll';
_reg_info['Dynamic Desktop Media adware']['{2BC43670-C0BD-4794-BB11-F60F3E001DC5}']['file'] = 'ddmp.dll';
_reg_info['Dynamic Desktop Media adware']['{2BC43670-C0BD-4794-BB11-F60F3E001DC5}']['url'] = 'http://www.spyany.com/program/article_spw_rm_Dynamic_Desktop_Media.html';
_reg_info['E2Give']['{3643ABC2-21BF-46B9-B230-F247DB0C6FD6}']['file'] = 'IeBHOs.dll';
_reg_info['eAcceleration StopSign']['{6ACD11BD-4CA0-4283-A8D8-872B9BA289B6}']['file'] = 'webcbrowse.dll';
_reg_info['EasyBar/Toolbarcash']['{C77E900A-FF55-400E-9BAA-E042C8212898}']['file'] = 'ToolbarStarter.dll';
_reg_info['EasySearch/UmaxSearch']['{FFFFFFFF-FFFF-FFFF-FFFF-FFFFFFFFFFFF}']['file'] = 'bin376.dll';
_reg_info['EliteBar/SearchMiracle adware']['{28CAEFF3-0F18-4036-B504-51D73BD81C3A}']['file'] = 'Elitebar.dll';
_reg_info['EliteBar/SearchMiracle adware']['{28CAEFF3-0F18-4036-B504-51D73BD81C3A}']['url'] = 'http://www.sunbeltsecurity.com/ThreatDisplay.aspx?tid=14899&cs=7E9A08E6440BB6B17C339F5DC5C816FA';
_reg_info['EliteBar/SearchMiracle adware']['{825CF5BD-8862-4430-B771-0C15C5CA880F}']['file'] = 'Elitebar.dll';
_reg_info['EliteBar/SearchMiracle adware']['{825CF5BD-8862-4430-B771-0C15C5CA880F}']['url'] = 'http://www.symantec.com/security_response/writeup.jsp?docid=2005-083109-1455-99';
_reg_info['EliteBar/SearchMiracle adware']['{FA6548E9-78F5-4025-9D7B-FC1367789C38}']['file'] = 'Elitebar.dll';
_reg_info['Enhancemysearch.com keyword hijacker']['{017C20C1-F86F-11D8-9B25-000ACD002AE3}']['file'] = 'Helper100.dll';
_reg_info['eSearch browser Hijacker']['{5C472352-90D0-4214-BF20-8E4A2B82F980}']['file'] = 'win32app.dll';
_reg_info['esyndicate.com/seeq.com toolbar']['{CC378B83-9577-44D0-B4F8-0DD965E176FC}']['file'] = 'esyn.dll';
_reg_info['eUniverse SearchNugget Toolbar']['{4E7BD74F-2B8D-469E-C0FF-FD7FF4D5FA7D}']['file'] = 'sbar.dll';
_reg_info['eUniverse SirSearch']['{4E7BD74F-2B8D-469E-C0FC-F76FA694BF2E}']['file'] = 'Searchbr.dll';
_reg_info['eUniverse/Keenvalue variant']['{269B6797-664E-48AA-B283-B012BDF6E525}']['file'] = 'BHO.dll';
_reg_info['eXact Advertising']['{AEECBFDA-12FA-4881-BDCE-8C3E1CE4B344}']['file'] = 'nvms.dll';
_reg_info['eXact Advertising']['{CE188402-6EE7-4022-8868-AB25173A3E14}']['file'] = 'mscb.dll';
_reg_info['eXact Advertising']['{F4E04583-354E-4076-BE7D-ED6A80FD66DA}']['file'] = 'msbe.dll';
_reg_info['eXact Search Bar']['{F9765480-72D1-11D4-A75A-004F49045A87}']['file'] = 'eXactToolbar.dll';
_reg_info['ExactSearch or MySearch']['{014DA6C1-189F-421a-88CD-07CFE51CFF10}']['file'] = 'eXacttoolbar.dll';
_reg_info['Excite Search bar']['{04719991-296F-4958-AA0F-FA25FFA5008B}']['file'] = 'X8bar.dll';
_reg_info['Excite Search bar']['{04719991-296F-4958-AA0F-FA25FFA5008B}']['url'] = 'http://www.excite.com/';
_reg_info['Expext/MetaDirect hijacker']['{23BC1CCF-4BE7-497F-B154-6ADA68425FBB}']['file'] = 'expext.dll';
_reg_info['EZCybersearch bar']['{760A9DDE-1433-4A7C-8189-D6735BB5D3DD}']['file'] = 'EzSearch.dll';
_reg_info['EZCybersearch/Surebar']['{D3F01312-8A3D-4D41-A4FA-FB61D295CB6B}']['file'] = 'Surebar.dll';
_reg_info['ezSearching']['{2F24B54D-3A27-11D8-8169-00C02623048A}']['file'] = 'Testadit3.dll';
_reg_info['ezSearching']['{34D516EA-40E3-4E3B-8BA8-505112738ED5}']['file'] = 'ctavp3.dll';
_reg_info['ezSearching']['{4B021269-DD24-48B2-96B4-DA121E9C0502}']['file'] = 'ctpp';
_reg_info['eZsearching']['{858126B0-3708-4051-AE8E-B48521401CA2}']['file'] = 'ctsr*.dll';
_reg_info['ezSearching']['{8DB672BD-330F-11D8-8168-00C02623048A}']['file'] = 'Testadit.dll';
_reg_info['ezSearching']['{AEFCDEC8-EB7D-429F-BC73-4F30D07BFE41}']['file'] = 'ctadl';
_reg_info['EZSearching']['{B6598677-4B54-42A9-BA67-8B64E3FCD92D}']['file'] = 'psic';
_reg_info['EZSearching']['{DB0018A2-F7D9-4B71-9651-640143DF23F9}']['file'] = 'ctap';
_reg_info['EZtracks/Pickoftheweb toolbar']['{3023AF97-870E-476A-B30E-3923DF2B84BD}']['file'] = 'eztracks_ieplug.dll';
_reg_info['Ezula TopText']['{58359010-BF36-11D3-99A2-0050DA2EE1BE}']['file'] = 'eabh.dll';
_reg_info['Ezula TopText']['{58359010-BF36-11D3-99A2-0050DA2EE1BE}']['url'] = 'http://www.cexx.org/toptext.htm';
_reg_info['FastFind adware variant']['{2E65A557-173C-4DE9-860B-28FC5CACA542}']['file'] = 'Setup.dll';
_reg_info['FastFind adware variant']['{2E65A557-173C-4DE9-860B-28FC5CACA542}']['url'] = 'http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_STARTPAG.KF&VSect=T';
_reg_info['FastFind adware variant']['{79C03BC5-6C55-4B5B-921F-C02B6F1ABD7B}']['file'] = 'Pribi.dll';
_reg_info['FastFind adware variant']['{79C03BC5-6C55-4B5B-921F-C02B6F1ABD7B}']['url'] = 'http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_STARTPAG.KF&VSect=T';
_reg_info['FastFind adware variant']['{9E992732-295F-4987-8BE3-16FAC1639198}']['file'] = 'IEService.dll';
_reg_info['FastFind adware variant']['{9E992732-295F-4987-8BE3-16FAC1639198}']['url'] = 'http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=TROJ_STARTPAG.KF&VSect=T';
_reg_info['FastFind.org SubSearch']['{00F16DC8-1B2A-42F4-B18B-E21DA9D2D7FD}']['file'] = '01A00.DLL';
_reg_info['FastFind.org SubSearch']['{2A57772A-D963-4533-A999-A4D66B7EF424}']['file'] = '00S00.dll';
_reg_info['FastFind.org SubSearch']['{BD0BA5CD-7C8E-47ED-935E-1ABBAC9B29E0}']['file'] = '88313.dll';
_reg_info['FastFind.org SubSearch']['{D97287B6-4018-4060-948D-54D2122FC5C3}']['file'] = '0002C00.dll';
_reg_info['FavoriteMan/FOne']['{000000F1-34E3-4633-87C6-1AA7A44296DA}']['file'] = 'FOne.dll';
_reg_info['FavoriteMan/SpyAssault']['{EBBD88E5-C372-469D-B4C5-1FE00352AB9B}']['file'] = 'ss32.dll';
_reg_info['FavoriteMan']['{000000DA-0786-4633-87C6-1AA7A4429EF1}']['file'] = 'emesx.dll';
_reg_info['FavoriteMan']['{00000EF1-0786-4633-87C6-1AA7A44296DA}']['file'] = 'ATPartners.dll';
_reg_info['FavoriteMan']['{00000EF1-34E3-4633-87C6-1AA7A44296DA}']['file'] = 'F1.dll';
_reg_info['FavoriteMan']['{139D88E5-C372-469D-B4C5-1FE00852AB9B}']['file'] = 'ofrg.dll';
_reg_info['FizzleWizzle search bar']['{9056A11F-5EA6-4A67-BDE9-8D3C7C453DAC}']['file'] = 'Iefwbar.dll';
_reg_info['FlashEnhancer']['{7CD20E91-1F31-41da-8379-479EA31DF969}']['file'] = 'XML.dll';
_reg_info['FlashTrack parasite']['{95795B67-BBAB-47d0-8A9F-069E8242C0E5}']['file'] = 'Fen.dll';
_reg_info['FlashTrack, Ftapp']['{63CF97E8-4133-438a-A831-CC9C6D47D673}']['file'] = 'Flcp.dll';
_reg_info['FlashTrack, Ftapp']['{665ACD90-4541-4836-9FE4-062386BB8F05}']['file'] = 'F';
_reg_info['FlashTrack']['{7371F073-AC0F-4b80-BB2F-96A488CEFB32}']['file'] = 'xm320.dll';
_reg_info['Flyswat']['{82B98006-7A56-11D2-A26F-00C04F962769}']['file'] = 'Flylib.dll';
_reg_info['Flyswat']['{82B98006-7A56-11D2-A26F-00C04F962769}']['url'] = 'http://accs-net.com/smallfish/flyswat.htm';
_reg_info['Foxxweb Interactive (Softomate) spyware - Foxxweb Interactive (spyware)']['{7D6BEC01-15E2-46F0-8ED3-D715DE09A8F9}']['file'] = '';
_reg_info['FriendGreetings E-Card foistware']['{7011471D-3F74-498E-88E1-C0491200312D}']['file'] = 'Otglove.dll';
_reg_info['FriendGreetings E-Card foistware']['{7011471D-3F74-498E-88E1-C0491200312D}']['url'] = 'http://vil.nai.com/vil/content/v_99760.htm';
_reg_info['Friends.fr. toolbar']['{08DBDE36-DF28-11D5-8CA5-0050DA44A764}']['file'] = 'Msvri.dll';
_reg_info['Friends.fr. toolbar']['{08DBDE36-DF28-11D5-8CA5-0050DA44A764}']['url'] = 'http://research.sunbelt-software.com/threatdisplay.aspx?threatid=47429';
_reg_info['from imu.com.cn']['{54F8C0E2-34F9-474F-B47F-2CFCFE2300A2}']['file'] = 'IMULiver.dll';
_reg_info['from imu.com.cn']['{9A0527C1-4D5F-4e45-9D28-6257F75EDDB1}']['file'] = 'imuiepls.dll';
_reg_info['Gamebar']['{4E7BD74F-2B8D-469E-C0FF-FD69B994BD7D}']['file'] = 'gamebar.dll';
_reg_info['Gamebar']['{4E7BD74F-2B8D-469E-C0FF-FD69B994BD7D}']['url'] = 'http://web.archive.org/web/20050306062234/http://member.game.net/Membership/Privacy.asp';
_reg_info['GamSYS']['{F36C1198-FC6B-4012-9928-DFA76FB56CC3}']['file'] = 'GAMhelper.dll';
_reg_info['Gigasearch hijacker']['{EADD3112-0CF8-444b-AC0F-EBA38E004554}']['file'] = 'giga32.dll';
_reg_info['Gigasearch.biz hijacker']['{C1EA1782-8E6E-4ea4-9800-B68DE41F1A26}']['file'] = 'gigasoft.dll';
_reg_info['Gigasearch.biz hijacker']['{C1EA1782-8E6E-4ea4-9800-B68DE41F1A26}']['url'] = 'http://www.f-secure.com/sw-desc/adware_w32_gigasearch.shtml';
_reg_info['Give4Free']['{208E7E77-507A-4649-B0C9-D39E9049C7A2}']['file'] = 'ibho.dll';
_reg_info['GoGoData toolbar']['{2D877C0B-3F44-42CD-A283-57AAA9186CB9}']['file'] = 'GoGoDataBar.dll';
_reg_info['GoGoData toolbar']['{2D877C0B-3F44-42CD-A283-57AAA9186CB9}']['url'] = 'http://web.archive.org/web/20041206213207/http://www.gogodata.com/toolbar/index.htm';
_reg_info['GoGoTools']['{1E1B2879-88FF-11D2-8D96-D7ACAC95951F}']['file'] = 'HTMLEdit.dll';
_reg_info['GoGoTools']['{76532682-A5C9-11d8-AE07-00D0591}']['file'] = 'SearchGogo.dll';
_reg_info['GoHip/Browserenh']['{BA3D9F56-5EC1-497D-881A-93A28F58D9AD}']['file'] = 'IE.dll';
_reg_info['GoZilla']['{CD4C3CF0-4B15-11D1-ABED-709549C10000}']['file'] = 'Goiehlp.dll';
_reg_info['Gratisware']['{5843A29E-1246-11D4-BA8C-0050DA707ACD}']['file'] = 'crs32.dll';
_reg_info['Grip Toolbar']['{08F46458-D00F-4573-8EB3-A9A9E15503F8}']['file'] = 'NetGuideBHO170.dll';
_reg_info['Grip Toolbar']['{4E7BD74F-2B8D-469E-A4E4-FC7CBD87BD7D}']['file'] = 'gripcz6.dll';
_reg_info['HDTbar']['{70B3DA2C-E02D-4ce0-B1F8-48320FD443D2}']['file'] = 'T2BHO.dll';
_reg_info['HDTbar']['{70B3DA2C-E02D-4ce0-B1F8-48320FD443D2}']['url'] = 'http://www.sunbeltsecurity.com/threatdisplay.aspx?name=HDTBar&tid=15102&cs=28951BF95F7CF1D6A3E89265728F773D';
_reg_info['HighTraffic']['{53E10C2C-43B2-4657-BA29-AAE179E7D35C}']['file'] = 'BHO2.dll';
_reg_info['HighTraffic']['{A8B9F08F-2FC4-4ADE-9049-CFBA586971BA}']['file'] = 'Bho2.dll';
_reg_info['hijacker,  as yet unidentified']['{22B9A67D-E689-44B6-B775-0E8FE84B4F9B}']['file'] = 'dll';
_reg_info['Hijacker,  as yet unidentified']['{4E7BD74F-2B8D-469E-A1F6-FC7EB590A97D}']['file'] = 'search3.dll';
_reg_info['Hijacker,  as yet unidentified']['{832BEBED-C3DA-4534-A2C2-B2FFF220C820}']['file'] = 'replaceSearch.dll';
_reg_info['Hijacker,  as yet unidentified']['{FC4C5EAE-66EE-11D4-BC67-0000E8E582D2}']['file'] = 'e2bho.dll';
_reg_info['Hijacker, as yet unidentified']['{397D7D63-816E-4ECF-8761-775C932C5CF1}']['file'] = 'iDonate.dll';
_reg_info['Hijacker, as yet unidentified']['{8085E374-ACBB-42F9-873F-49EC7E244F97}']['file'] = '';
_reg_info['Hijacker, unidentified']['{BEB133E5-FD72-43b7-8AFF-681831CC72D9}']['file'] = 'wiesasp2.dll';
_reg_info['Hijacker, unidentified']['{BEB133E5-FD72-43b7-8AFF-681831CC72D9}']['url'] = 'http://research.sunbelt-software.com/threatdisplay.aspx?threatid=13043';
_reg_info['HotBar']['{204F937E-519E-4597-96FA-8F1F59F3CB6D}']['file'] = 'ctor.dll';
_reg_info['Hotbar']['{B195B3B3-8A05-11D3-97A4-0004ACA6948E}']['file'] = 'Hbhostie.dll';
_reg_info['Httper']['{A5483501-070C-41DD-AF44-9BD8864B3015}']['file'] = 'httper.dll';
_reg_info['HuntBar/Stoolbar']['{0A5CF411-F0BF-4AF8-A2A4-8233F3109BED}']['file'] = 'Stoolbar.dll';
_reg_info['HuntBar/WinTools, adware variant']['{8DA5457F-A8AA-4CCF-A842-70E6FD274094}']['file'] = 'WToolsT.dll';
_reg_info['HuntBar/Wintools']['{87766247-311C-43B4-8499-3D5FEC94A183}']['file'] = 'WToolsB.dll';
_reg_info['HuntBar']['{0A68C5A2-64AE-4415-88A2-6542304A4745}']['file'] = 'Msiets.dll';
_reg_info['Huntbar']['{63B78BC1-A711-4D46-AD2F-C581AC420D41}']['file'] = 'Btiein.dll';
_reg_info['HuntBar']['{8952A998-1E7E-4716-B23D-3DBE03910972}']['file'] = 'Toolbar.dll';
_reg_info['Huntbar']['{A6250FB8-2206-499E-A7AA-E1EC437E71C0}']['file'] = 'Msielink.dll';
_reg_info['HuntBar']['{D6DFF6D8-B94B-4720-B730-1C38C7065C3B}']['file'] = 'Btlink.dll';
_reg_info['HuntBar']['{D6E66235-7AA6-44ED-A06C-6F2033B1D993}']['file'] = 'Msiein.dll';
_reg_info['iChoose browser enhancement']['{B40A6610-1D16-11D3-80B2-005004994DA2}']['file'] = 'Bpieclient.dll';
_reg_info['iChoose browser enhancement']['{B40A6610-1D16-11D3-80B2-005004994DA2}']['url'] = 'http://web.archive.org/web/20080415060307/http://www.luckysoftware.dk/ichoose.php';
_reg_info['Icoo Loader']['{0519A9C9-064A-4cbc-BC47-D0EACD581477}']['file'] = 'icooue.dll';
_reg_info['Icoo Loader']['{465A59EC-20E5-4fca-A38A-E5EC3C480218}']['file'] = 'icoou.dll';
_reg_info['Icoo Loader']['{BA7270AE-5636-4618-BAF3-F86ADA39F036}']['file'] = 'icoourl.dll';
_reg_info['Icoo Loader']['{ED657BAF-1EE5-4A07-9D2E-6D0525EFC69B}']['file'] = 'icoourlext.dll';
_reg_info['IE Redirector.  browser hijacker']['{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE53}']['file'] = 'Ieredir.dll';
_reg_info['IeMonit']['{CE7C3CF0-4B15-11D1-ABED-709549C10001}']['file'] = 'iemonit.dll';
_reg_info['IEPlugin variant']['{01F44A8A-8C97-4325-A378-76E68DC4AB2E}']['file'] = 'systb.dll';
_reg_info['IEplugin']['{69135BDE-5FDC-4B61-98AA-82AD2091BCCC}']['file'] = 'systb.dll';
_reg_info['IEPlugin']['{914AFB33-550B-4BD0-B4EF-8DA185504836}']['file'] = 'Winobject.dll';
_reg_info['IESearch toolbar hijacker']['{2C5175A2-ADF3-4F57-AB70-BA90FD60A383}']['file'] = 'IESearchToolbar.dll';
_reg_info['IESearch toolbar hijacker']['{2C5175A2-ADF3-4F57-AB70-BA90FD60A383}']['url'] = 'http://www.w7forums.com/hide-remove-ie8-search-box-t433.html';
_reg_info['IESearch Toolbar']['{2c5175a2-adf3-4f57-ab70- ba90fd60a383}']['file'] = 'IESEARCHTOOLBAR.DLL';
_reg_info['IESearch Toolbar']['{2c5175a2-adf3-4f57-ab70- ba90fd60a383}']['url'] = 'http://www.w7forums.com/hide-remove-ie8-search-box-t433.html';
_reg_info['IETray']['{BD51AEC6-7991-4A60-94D6-D5FEBB655D10}']['file'] = 'IEMsg.dll';
_reg_info['iGetNet/Natural Language Navigation']['{60E78CAC-E9A7-4302-B9EE-8582EDE22FBF}']['file'] = 'BHO001.DLL';
_reg_info['IGN Keywords']['{730F2451-A3FE-4A72-938C-FC8A74F15978}']['file'] = 'Bho.dll';
_reg_info['iLookup parasite variant']['{9FF528A9-7314-4658-B497-3D1D4597B300}']['file'] = 'wingss32.dll';
_reg_info['i-lookup search bar']['{61D029AC-972B-49FE-A155-962DFA0A37BB}']['file'] = 'Ineb.dll';
_reg_info['i-lookup search bar']['{FBAA0B9E-A059-43E4-9699-76EB0AEB975B}']['file'] = 'Gws.dll';
_reg_info['i-lookup/Abeb']['{2038A287-4221-4F76-A7C0-ADDD77AFABB3}']['file'] = 'abeb.dll';
_reg_info['i-Lookup/Bmeb']['{753AA023-02D1-447D-8B55-53A91A5ABF18}']['file'] = 'Bmeb.dll';
_reg_info['i-Lookup/Chgrgs']['{35CC7369-C6EB-4A64-AB05-44CF0B5087A0}']['file'] = 'Chgrgs.dll';
_reg_info['i-Lookup/Chgrgs']['{C82B55F0-60E0-478C-BC55-E4E22F11301D}']['file'] = 'Chgrgs.dll';
_reg_info['i-lookup/Drbr']['{2D556983-83D7-4630-9AA5-27C74CA27B79}']['file'] = 'Drbr.dll';
_reg_info['i-Lookup/GlobalWebSearch']['{E539DEA3-BA67-4F1F-A897-5F2F4F29A063}']['file'] = 'winenc32.dll';
_reg_info['i-lookup/Sbus']['{19A447BA-9C2E-4864-93F5-A0645229771E}']['file'] = 'Sbus.dll';
_reg_info['I-Lookup']['{18B79968-1A76-4953-9EBB-B651407F8998}']['file'] = 'winenc32.dll';
_reg_info['I-Lookup']['{CBA523B2-1906-4D14-95A2-CD8E233701C7}']['file'] = 'waeb.dll';
_reg_info['iMesh']['{00000000-6CB0-410C-8C3D-8FA8D2011D0A}']['file'] = 'iMeshBHO.dll';
_reg_info['iMesh']['{00000000-6CB0-410C-8C3D-8FA8D2011D0A}']['url'] = 'http://www.spyany.com/program/article_spw_rm_IMesh.html';
_reg_info['IncrediFind variant']['{00D6A7E7-4A97-456f-848A-3B75BF7554D7}']['file'] = 'PerfectNavBHO.dll';
_reg_info['IncrediFind variant']['{0428FFC7-1931-45b7-95CB-3CBB919777E1}']['file'] = 'PerfectNavBHO.dll';
_reg_info['IncrediFind variant']['{A045DC85-FC44-45be-8A50-E4F9C62C9A84}']['file'] = 'PerfectNavBHO.dll';
_reg_info['Incredifind/Keenvalue']['{0199DF25-9820-4bd5-9FEE-5A765AB4371E}']['file'] = 'IncFindBHO170.dll';
_reg_info['IncrediFind/Keenvalue']['{01CD4DDA-166D-4831-A373-ACCC27E1BB9D}']['file'] = 'IncFindBHO150c.dll';
_reg_info['IncrediFind/Keenvalue']['{4FC95EDD-4796-4966-9049-29649C80111D}']['file'] = 'incfindbho.dll';
_reg_info['IncrediFind/Keenvalue']['{5D60FF48-95BE-4956-B4C6-6BB168A70310}']['file'] = 'incfindbho.dll';
_reg_info['InetSpeak/Iexplorr']['{388D7EBB-CBB9-4126-8DB2-86DC6863A206}']['file'] = 'iexplorr11.dll';
_reg_info['InetSpeak/Iexplorr']['{39AF31DD-EAFC-45EA-A56C-385B52E25CC0}']['file'] = 'iexplorr22.dll';
_reg_info['InetSpeak/Iexplorr']['{4CEBBC6B-5CEE-4644-80CF-38980BAE93F6}']['file'] = 'Iexplorr23.dll';
_reg_info['InetSpeak/Iexplorr']['{54ED9B49-81D1-4866-95A6-30F01DE0047E}']['file'] = 'iexplorr29.dll';
_reg_info['InetSpeak/Iexplorr']['{6B12DABB-0B7C-44FA-B0B3-4BAFF3790256}']['file'] = 'Iexplorr24.dll';
_reg_info['InetSpeak/Iexplorr']['{90E34F98-E3E6-4CD7-A592-E964FED8AF78}']['file'] = 'iexplorr26.dll';
_reg_info['InetSpeak/Iexplorr']['{94326E3F-F51F-4863-A832-4ACD0D7D4BC3}']['file'] = 'iexplorr27.dll';
_reg_info['InetSpeak/Iexplorr']['{A76066C9-941B-4209-9D96-0AC80501100D}']['file'] = 'iexplorr11.dll';
_reg_info['InetSpeak/Iexplorr']['{A76066C9-941B-4209-9D96-0AC80501100D}']['url'] = 'http://www.symantec.com/security_response/print_writeup.jsp?docid=2005-060222-0943-99';
_reg_info['InetSpeak/Iexplorr']['{BC0D2038-2DE5-4A6F-92BC-B18A3E0DE32A}']['file'] = 'iexplorr11.dll';
_reg_info['InetSpeak']['{2E12B523-3D4C-4FAC-9B04-0376A8F5E879}']['file'] = 'WindowsIE.dll';
_reg_info['InetSpeak']['{D6862A22-1DD6-11D3-BB7C-444553540000}']['file'] = 'Bho.dll';
_reg_info['InstaFinder hijacker']['{4E7BD74F-2B8D-469E-DCF7-F96DA086B434}']['file'] = 'instafin.dll';
_reg_info['IPInsight']['{000004CC-E4FF-4F2C-BC30-DBEF0B983BC9}']['file'] = 'Ipinsigt.dll';
_reg_info['IS Technologies SideFind']['{A3FDD654-A057-4971-9844-4ED8E67DBBB8}']['file'] = 'sfbho.dll';
_reg_info['iSearch Desktop Search toolbar']['{5B4AB8E2-6DC5-477A-B637-BF3C1A2E5993}']['file'] = 'sysupd.dll';
_reg_info['iSearch toolbar']['{1C78AB3F-A857-482e-80C0-3A1E5238A565}']['file'] = 'toolbar.dll';
_reg_info['iSearch toolbar']['{1C78AB3F-A857-482e-80C0-3A1E5238A565}']['url'] = 'http://www.kephyr.com/spywarescanner/library/isearch/index.phtml';
_reg_info['i-search.us hijacker']['{8F5A62E2-71F2-72D3-E045-DDF234CAE228}']['file'] = 'Isearch2.dll';
_reg_info['i-search.us hijacker']['{ECAD9C14-ED46-D58A-E847-ADBEFC8D37EB}']['file'] = 'IBHO2.DLL';
_reg_info['iWon Search Assistant']['{08E1C8E1-E565-44fc-A766-C9539BB3ABB7}']['file'] = 'I1srchas.dll';
_reg_info['iWon Toolbar']['{C298fb42-e3e2-11d3-adcd-0050dac24e8f}']['file'] = 'Iwonbar.dll';
_reg_info['iWon Toolbar']['{C298fb42-e3e2-11d3-adcd-0050dac24e8f}']['url'] = 'http://www.ehow.com/facts_7369473_information-iwon_mywebsearch-spyware.html';
_reg_info['JimmySurf']['{5998B08E-CFAC-11D5-822A-0050048E6E38}']['file'] = 'SurfPlugin.dll';
_reg_info['KeenValue/Powersearch variant']['{4E7BD74F-2B8D-469E-DFF7-EC7DA787AD2D}']['file'] = 'Pwrsqsim.dll';
_reg_info['KeenValue/PowerSearch']['{4E7BD74F-2B8D-469E-A3EE-FB7FA682AA7D}']['file'] = 'pwrsdp1.dll';
_reg_info['KeenValue/PowerSearch']['{4E7BD74F-2B8D-469E-A3FA-F161A787AD2D}']['file'] = 'pwrsmnd1.dll';
_reg_info['KeenValue/PowerSearch']['{4E7BD74F-2B8D-469E-C0FC-F378A787AD2D}']['file'] = 'Toolbarpwrstlbr.dll';
_reg_info['KeenValue/PowerSearch']['{4E7BD74F-2B8D-469E-C8FB-FC6DA787AD2D}']['file'] = 'pwrsacez.dll';
_reg_info['KeenValue/PowerSearch']['{4E7BD74F-2B8D-469E-D4FF-ED78A787AD2D}']['file'] = 'pwrstraf.dll';
_reg_info['Keylogger, probably LoveTester related']['{DCE80CA4-B555-44D8-B423-A75D6C345EE1}']['file'] = 'stype10.dll';
_reg_info['Keywords']['{F104576A-91BA-40AD-91DE-2C20801339AB}']['file'] = 'Keywords001.dll';
_reg_info['Kugoo IEHelper']['{748A5D0A-68D3-11D4-A67E-00E098823A80}']['file'] = 'Iehelper.dll';
_reg_info['Kugoo IEHelper']['{B3ECCAC9-C7FA-462C-894B-8E9930A70E14}']['file'] = 'IEHelper';
_reg_info['LinkReplacer hijacker variant']['{6A6E50DC-BFA8-4B40-AB1B-159E03E829FD}']['file'] = 'lmf32.dll';
_reg_info['LinkReplacer']['{66993893-61B8-47DC-B10D-21E0C86DD9C8}']['file'] = 'iehelper.dll';
_reg_info['Linkz.com AdBlock']['{08C63920-DC18-11D2-9E1E-00A0247061AB}']['file'] = 'Aphelper.dll';
_reg_info['Linkz.com AdBlock']['{08C63920-DC18-11D2-9E1E-00A0247061AB}']['url'] = 'http://www.spywareguide.com/spydet_868_adblock.html';
_reg_info['LookThru Cool Search Bar']['{2AF8CED6-5BD8-4310-A90C-9664EFB16B10}']['file'] = 'coolbar.dll';
_reg_info['Lop.com']['{D44B5436-B3E4-4595-B0E9-106690E70A58}']['file'] = 'plg_ie0.dll';
_reg_info['LoveTester foistware']['{43FA5935-E36E-4937-8127-A90191B2EC68}']['file'] = 'domain11.dll';
_reg_info['LoveTester foistware']['{72557F9F-13AE-44C9-B3D7-5091B599027C}']['file'] = 'smail11.dll';
_reg_info['LZIO.com adware']['{00000000-0000-0000-8835-3EFF76BF2657}']['file'] = 'kw3eef76.dll';
_reg_info['LZIO.com adware']['{00000000-0000-0000-8835-3EFF76BF2657}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-0000-0000-BFA1-D7EE6696B865}']['file'] = 'icdd7ee6.dll';
_reg_info['LZIO.com adware']['{00000000-0000-0000-BFA1-D7EE6696B865}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-0000-41a3-98CF-00000000168B}']['file'] = 'wm41a398.dll';
_reg_info['LZIO.com adware']['{00000000-0000-41a3-98CF-00000000168B}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-0000-47c5-A90F-2CDE8F7638DB}']['file'] = 'iel2cde8.dll';
_reg_info['LZIO.com adware']['{00000000-0000-47c5-A90F-2CDE8F7638DB}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-10D6-4e5f-8F7F-29B32C1C0FC4}']['file'] = 'icddefff.dll';
_reg_info['LZIO.com adware']['{00000000-10D6-4e5f-8F7F-29B32C1C0FC4}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-167B-41bc-95FF-86A07B14712C}']['file'] = 'he3bbcff.dll';
_reg_info['LZIO.com adware']['{00000000-167B-41bc-95FF-86A07B14712C}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-2565-4c5b-A455-A74C8A2247AB}']['file'] = 'wmcbaaca.dll';
_reg_info['LZIO.com adware']['{00000000-2565-4c5b-A455-A74C8A2247AB}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{00000000-64C4-4a64-9767-895AB4921E41}']['file'] = 'ielcaabe.dll';
_reg_info['LZIO.com adware']['{00000000-64C4-4a64-9767-895AB4921E41}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{000E6ED5-E3FC-4c93-99E9-D38D2A9F9B09}']['file'] = 'he3e3fc4.dll';
_reg_info['LZIO.com adware']['{000E6ED5-E3FC-4c93-99E9-D38D2A9F9B09}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{0D7DC475-59EB-4781-985F-A6F5D4E2BC73}']['file'] = 'Lie1D6Ff.dll';
_reg_info['LZIO.com adware']['{0D7DC475-59EB-4781-985F-A6F5D4E2BC73}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['LZIO.com adware']['{3BC2C2D1-758E-4912-BED2-AE50DE69E8AF}']['file'] = 'iedcb1f5.dll';
_reg_info['LZIO.com adware']['{3BC2C2D1-758E-4912-BED2-AE50DE69E8AF}']['url'] = 'http://www.spywareguide.com/product_show.php?id=853';
_reg_info['MacigControl']['{DE614603-6320-4046-A7A7-6A69CEC26F14}']['file'] = '4b_1,0,0,5_navpmc.dll';
_reg_info['Make-deal.com malware']['{2A7B720A-7A28-4e99-80A0-2DF985EC93D0}']['file'] = 'Font.dll';
_reg_info['Malware taking advantage of the ASN.1 exploit']['{00673769-777F-4814-BE0F-74CBA1D823B8}']['file'] = 'Iehook.dll';
_reg_info['Matrix Technology Network 123Mania']['{622CC208-B014-4FE0-801B-874A5E5E403A}']['file'] = 'GIDCAI32.DLL';
_reg_info['Matrix Technology Network 123Mania']['{9C5B2F29-1F46-4639-A6B4-828942301D3E}']['file'] = 'SIPSPI32.DLL';
_reg_info['Medialoads Enhanced/Downloadware']['{85A702BA-EA8F-4B83-AA07-07A5186ACD7E}']['file'] = 'ME';
_reg_info['MediaUpdate/SafeSurfing']['{D8E25C53-9508-4f5c-9249-D98D438891D5}']['file'] = 'ssurf022.dll';
_reg_info['MediaUpdate']['{B8C0220D-763D-49A4-95F4-61DFDEC66EE6}']['file'] = 'MEDUP012.DLL';
_reg_info['Mega! Search:  best-search.us hijacker']['{8BC6346B-FFB0-4435-ACE3-FACA6CD77816}']['file'] = 'MegaHost.dll';
_reg_info['MegaSearch']['{4E7BD74F-2B8D-469E-C0FF-FA7FB592BF30}']['file'] = 'megasear.dll';
_reg_info['Meridian popupper']['{FA79FA22-8DB3-43D1-997B-6DBFD8845569}']['file'] = 'Myaccess.dll';
_reg_info['Meridian popupper']['{FA79FA22-8DB3-43D1-997B-6DBFD8845569}']['url'] = 'http://www.f-secure.com/sw-desc/meridian_popupper.shtml';
_reg_info['MidAddle adware']['{E8EAEB34-F7B5-4C55-87FF-720FAF53D841}']['file'] = 'midaddle.dll';
_reg_info['MidAddle adware']['{E8EAEB34-F7B5-4C55-87FF-720FAF53D841}']['url'] = 'http://www.adrants.com/2004/06/adspyre-launches-midaddle-ad-system.php';
_reg_info['MoneyTree/DyFuCa']['{8F4E5661-F99E-4B3E-8D85-0EA71C0748E4}']['file'] = 'Wsem';
_reg_info['MPGcom toolbar']['{FFFFFFFF-FFFF-FFFF-FFFF-5F8507C5F4E9}']['file'] = 'iempg.dll';
_reg_info['MPGcom toolbar']['{FFFFFFFF-FFFF-FFFF-FFFF-5F8507C5F4E9}']['url'] = 'http://www.xblock.com/product_show.php?id=726';
_reg_info['Msinfosys/AutoSearch hijacker']['{44A23DAB-8D31-43AE-9F68-5AC24CF7CE8C}']['file'] = 'Msinfosys.dll';
_reg_info['MSN SmartTags']['{9DD4258A-7138-49C4-8D34-587879A5C7A4}']['file'] = 'Msnbho.dll';
_reg_info['MultiMPP.com adware']['{002EB272-2590-4693-B166-FBD5D9B6FEA6}']['file'] = 'multimpp.dll';
_reg_info['Muul.com SiteHistory  hijacker']['{0345B059-8731-42BC-B7B7-5121014B02C6}']['file'] = 'ChangeURL_30.dll';
_reg_info['Myaopop Adware']['{204E9F8F-38CA-4E11-BA91-06B685285CC0}']['file'] = 'xpllog.dll';
_reg_info['MyBHOSpy (suspected spyware)']['{C52CBAEC-D969-4635-9F50-426CC15CE463}']['file'] = '413';
_reg_info['MyPageFinder']['{27A5FF76-9919-492C-98E3-EDA3502FC829}']['file'] = 'ml_32.dll';
_reg_info['MyTotalSearch']['{00BD2861-C654-4694-A44A-98642D73247D}']['file'] = 'MTSSRCAS.DLL';
_reg_info['MyTotalSearch']['{094176F1-BF35-4bcb-B68A-108DFB8C3825}']['file'] = 'MTSBAR.DLL';
_reg_info['Naupoint toolbar']['{0036F389-FEF8-43AC-9220-16430E0012ED}']['file'] = 'iEBINST.dll';
_reg_info['Naupoint toolbar']['{44FD0AF8-9D30-4E96-8ECE-306446B5E0D3}']['file'] = 'iEBINST2.dll';
_reg_info['Naupoint toolbar']['{4E7BD74F-2B8D-469E-95BE-B378BA9CB52D}']['file'] = 'Naupointbar.dll';
_reg_info['Naupoint toolbar']['{60261C06-81B0-4DE0-9313-E5BA203A64E9}']['file'] = 'pdfmgr.dll';
_reg_info['Naupoint toolbar']['{6375B3AD-4440-4C1F-95E5-A24198ED671C}']['file'] = 'sp1.dll';
_reg_info['NavExcel browser helper']['{C1E58A84-95B3-4630-B8C2-D06B77B7A0FC}']['file'] = 'Nhelper.dll';
_reg_info['NavExcel']['{D80C4E21-C346-4E21-8E64-20746AA20AEB}']['file'] = 'NavExcelBar.dll';
_reg_info['NeoToolbar']['{722E8B26-1C44-460F-88BB-50C82B20E30E}']['file'] = 'msqsb.dll';
_reg_info['Netguarder Web Cleaner']['{F585D290-1BF4-480A-AEC2-4182593F1E32}']['file'] = 'Webtool.dll';
_reg_info['Netguarder Web Cleaner']['{F585D290-1BF4-480A-AEC2-4182593F1E32}']['url'] = 'http://research.sunbelt-software.com/threatdisplay.aspx?threatid=8964';
_reg_info['NetNucleus/Mirar webband']['{528DA727-EC08-461E-9564-DF5C971E8574}']['file'] = 'WinNB40.dll';
_reg_info['NetNucleus/Mirar webband']['{528DA727-EC08-461E-9564-DF5C971E8574}']['url'] = 'http://www.kephyr.com/spywarescanner/library/mirartoolbar.winnb40/index.phtml';
_reg_info['NetNucleus/Mirar webband']['{8A0DCBDA-6E20-489C-9041-C1E8A0352E75}']['file'] = 'NN_Bar.dll';
_reg_info['NetNucleus/Mirar webband']['{8A0DCBDA-6E20-489C-9041-C1E8A0352E75}']['url'] = 'http://www.kephyr.com/spywarescanner/library/mirartoolbar/index.phtml';
_reg_info['NetNucleus/Mirar webband']['{9A9C9B69-F908-4AAB-8D0C-10EA8997F37E}']['file'] = 'WinNB';
_reg_info['NetPal/PrizePopper']['{C7ADE150-743D-11D4-8141-00E029626F6A}']['file'] = 'KER7120.DLL';
_reg_info['NetPal']['{000E7270-CC7A-0786-8E7A-DA09B51938A6}']['file'] = 'n3tpa1.dll';
_reg_info['Netpal']['{6085FB5B-C281-4B9C-8E5D-D2792EA30D2F}']['file'] = 'Netpal.dll';
_reg_info['Netster Smart Browse Toolbar']['{B98F79F4-3619-49FB-A7E7-B737E58C5727}']['file'] = 'netster.dll';
_reg_info['Netster Smart Browse Toolbar']['{B98F79F4-3619-49FB-A7E7-B737E58C5727}']['url'] = 'http://web.archive.org/web/20021113213714/http://at.netster.com/Index.asp?Site=YXQubmV0c3Rlci5jb20=';
_reg_info['New.Net QuickSearch']['{82315A18-6CFB-44a7-BDFD-90E36537C252}']['file'] = 'QuickSearchBar';
_reg_info['NewDotNet']['{4A2AACF3-ADF6-11D5-98A9-00E018981B9E}']['file'] = 'newdotnet';
_reg_info['NewtonKnows search bar']['{EE392A64-F30B-47C8-A363-CDA1CEC7DC1B}']['file'] = 'Bar.dll';
_reg_info['NewtonKnows toolbar variant']['{E9407738-A996-421A-A309-5C93C699E10A}']['file'] = 'ntoolbar.dll';
_reg_info['NJStar Asian Explorer']['{1E1B2879-30C7-11D4-8DDF-525400E483E3}']['file'] = 'ETop100.dll';
_reg_info['NJStar Asian Explorer']['{1E1B2879-30C7-11D4-8DDF-525400E483E3}']['url'] = 'http://www.njstar.com/asianexplorer/';
_reg_info['Not yet identified malware']['{40205287-E793-41AC-B95C-D8D064BA33CA}']['file'] = 'mscfg.dll';
_reg_info['NovaPortal adware']['{79C9FB71-7827-11D3-8DF7-00105A119B7C}']['file'] = 'NPBH.dll';
_reg_info['NovaPortal adware']['{79C9FB71-7827-11D3-8DF7-00105A119B7C}']['url'] = 'http://www.clickz.com/news/article.php/177951';
_reg_info['Oasisnet.com Hijacker/web downloader']['{37A5FF76-9919-492C-98E3-EDA3502FC829}']['file'] = 'Oasis.dll';
_reg_info['OnWebMedia adware variant']['{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE51}']['file'] = 'AdEnh.dll';
_reg_info['OnWebMedia adware variant']['{C68AE9C0-0909-4DDC-B661-C1AFB9F5AE56}']['file'] = 'AdEnh.dll';
_reg_info['OpinionBar']['{6607C683-AE7C-11D4-ACD7-0050DAC291A2}']['file'] = 'Myiemonitor.dll';
_reg_info['P0rn related malware']['{8403CB53-12B3-4537-9DEC-4F12F70A883D}']['file'] = 'thehun.dll';
_reg_info['p0rn related']['{13F90341-AD79-4A9F-9B57-0234675670D6}']['file'] = 'Ipsysdrv32.dll';
_reg_info['p0rn related']['{1E1B2879-88FF-11D2-8D96-D7ACAC97972F}']['file'] = 'Msudp.dll';
_reg_info['P0rn related']['{2E77E33F-671E-4334-ABAA-0C2E2BE654F1}']['file'] = 'mdv_32.dll';
_reg_info['Parasite, as yet unidentified']['{EFF80427-F837-4B74-8834-BAF18E0553FD}']['file'] = 'dll';
_reg_info['PASSGRAB, a spam relayer, hijacker and email account password stealer']['{81A35F39-4850-474E-92C9-B4CF283207E0}']['file'] = 'mstask64.dll';
_reg_info['PBar']['{42132494-F48F-4187-ABC8-0F343AD2E465}']['file'] = 'Pbshmd.dll';
_reg_info['PeopleOnPage/AproposMedia']['{01C5BF6C-E699-4CD7-BEA1-786FA05C83AB}']['file'] = 'AproposPlugin.dll';
_reg_info['PeopleOnPage/AproposMedia']['{65C8C1F5-230E-4DC9-9A0D-F3159A5E7778}']['file'] = 'pop';
_reg_info['Personal Antispy keylogger']['{1E1B2879-88FF-11D3-8D96-D7ACAC95951A}']['file'] = 'Funnywb.dll';
_reg_info['PickOfTheWeb toolbar']['{4E7BD74F-2B8D-469E-C0FF-FD7BA09AAA7D}']['file'] = 'potwbar.dll';
_reg_info['PolyFilter']['{0140DF95-9128-4053-AE72-F43F0CFCA062}']['file'] = 'SiKernel.dll';
_reg_info['Popmonster adware']['{4209B4C1-1295-4908-9312-A53C036EB3CD}']['file'] = 'BHO.dll';
_reg_info['Porn Hijacker']['{2FF5573C-0EB5-43db-A1B2-C4326813468E}']['file'] = 'iehr.dll';
_reg_info['porn hijacker']['{3E307D7F-5F68-4ddb-9294-EE230950F60C}']['file'] = 'winacl.dll';
_reg_info['power-linking-profits.com toolbar']['{D6223CBC-A263-4CB1-B35E-1AE40FEF3B3B}']['file'] = 'ietoolbar.dll';
_reg_info['PowerSearch toolbar']['{4E7BD74F-2B8D-469E-A58D-8F6FA787AD2D}']['file'] = 'PWRSC037.DLL';
_reg_info['PrecisionPop adware']['{68513770-A18E-11D7-B77C-00C0DFF3F600}']['file'] = 'Helper.dll';
_reg_info['ProBot Activity Monitor']['{312FA154-E1B7-4336-9833-EE6B38D58B56}']['file'] = 'pbcommon.dll';
_reg_info['Push toolbar']['{4E7BD74F-2B8D-469E-A0E8-F76FA694BF2E}']['file'] = 'searchv2.dll';
_reg_info['Qcbar/AdultLinks']['{765E6B09-6832-4738-BDBE-25F226BA2AB0}']['file'] = 'allch.dll';
_reg_info['Qcbar/AdultLinks']['{D6FC35D1-04AB-4D40-94CF-2E5AE4D0F8D2}']['file'] = 'llch.dll';
_reg_info['QuickFlicks Streaming Player']['{1E6F1D6A-1F20-11D4-8859-00A0CCE26836}']['file'] = 'SVAplayer.dll';
_reg_info['RedV Protector Suite']['{9C777253-3E17-42d6-897A-11B8617A8F7C}']['file'] = 'IELib.dll';
_reg_info['RedV Protector Suite']['{9C777253-3E17-42d6-897A-11B8617A8F7C}']['url'] = 'http://web.archive.org/web/20031211051344/http://services.bee.net/redv/protectorsuite/';
_reg_info['RelatedLinks adware']['{EFD84954-6B46-42f4-81F3-94CE9A77052D}']['file'] = 'lbbho.dll';
_reg_info['RelatedLinks adware']['{EFD84954-6B46-42f4-81F3-94CE9A77052D}']['url'] = 'http://www.kephyr.com/spywarescanner/library/relatedlinks.lbbho/index.phtml';
_reg_info['Ride MG adware']['{CE7EF827-47CC-48EB-B570-C367F1E1277E}']['file'] = 'x1ff.dll';
_reg_info['Roings.com adware']['{F2863EDE-7980-443A-AEA2-0F46076D590F}']['file'] = 'Wat.dll';
_reg_info['SafeguardProtect/Veevo']['{564FFB73-9EEF-4969-92FA-5FC4A92E2C2A}']['file'] = 'sfg_';
_reg_info['SafeguardProtect/Veevo']['{6CDF3C49-20E6-48d7-811B-9F5DD17F1D90}']['file'] = 'sfg****.dll';
_reg_info['SafeguardProtect/Veevo']['{6E1C5E3D-A8E6-4a92-820F-BFCFE45BA158}']['file'] = 'veev';
_reg_info['SafeguardProtect/Veevo']['{6E34D984-4054-45E3-8452-0159A2F0D232}']['file'] = 'Veevo.dll';
_reg_info['SafeguardProtect/Veevo']['{83B3E0C1-DEF1-4df5-A3F5-92D10B7A396A}']['file'] = 'sfg';
_reg_info['SafeguardProtect/Veevo']['{A23AB93D-6CFF-442c-BB8A-41F6145F47E7}']['file'] = 'PDF';
_reg_info['SafeguardProtect/Veevo']['{A44B961C-8C36-470f-8555-EDA0EFC1E710}']['file'] = 'popupblocker.dll';
_reg_info['SafeguardProtect/Veevo']['{B824E7B0-E8E3-4D75-895E-2C309EA4CC5D}']['file'] = 'Sgpopupblocker.dll';
_reg_info['SafeguardProtect/Veevo']['{D4D505DF-D582-400c-91B6-84921012AFE3}']['file'] = 'pdf';
_reg_info['SafeguardProtect/Veevo']['{E9C1FD9A-46B0-4185-84ED-E2F8ACD4A262}']['file'] = 'kdp';
_reg_info['SafeguardProtect/Veevo']['{F281FFC7-6C63-4bf9-83F2-AB7A6157B109}']['file'] = 'kdpupd.dll';
_reg_info['SafeSurfing parasite variant']['{7412C042-43B8-4F63-AEF3-E786DFAD1484}']['file'] = 'imwire28.dll';
_reg_info['SafeSurfing parasite variant']['{7412C042-43B8-4F63-AEF3-E786DFAD1484}']['url'] = 'http://research.sunbelt-software.com/threatdisplay.aspx?threatid=14990';
_reg_info['SBSoft IWantSearch hijacker']['{30192F8D-0958-44E6-B54D-331FD39AC959}']['file'] = 'rundlg32.dll';
_reg_info['SBSoft Web-Search hijacker variant, a member of the CoolWebSearch parasite family']['{30192F8D-0958-44E6-B54D-331FD39AC959}']['file'] = 'webdlg32.dll';
_reg_info['SBSoft/EZFinder.com hijacker']['{0CA6C3EA-2054-4011-BC9F-8BBC017A169C}']['file'] = 'uns.dll';
_reg_info['SBSoft/EZFinder.com hijacker']['{0CA6C3EA-2054-4011-BC9F-8BBC017A169C}']['url'] = 'http://vil.nai.com/vil/content/v_133779.htm';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-96F7-EB6DB99AA92E}']['file'] = 'gssomatic.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-96F7-EB6DB99AA92E}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-98F7-EB6DB99AA93B}']['file'] = 'ifsomatic.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-98F7-EB6DB99AA93B}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-C0FB-EF60B19DA02A}']['file'] = 'Wzhelper.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-C0FB-EF60B19DA02A}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.wzhelper/index.phtml';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-C0FB-EF60B19DBC34}']['file'] = 'ifhelper.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-C0FB-EF60B19DBC34}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-D1F7-EB6DB99AA97D}']['file'] = 'somatic.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-D1F7-EB6DB99AA97D}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.somatic/index.phtml';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-D7E4-F660B597BF2A}']['file'] = 'Webalize.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-D7E4-F660B597BF2A}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.webalize/index.phtml';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-DFF7-EC6BF4D5FA7D}']['file'] = 'gsim.dll';
_reg_info['SearchCentrix adware variant']['{4E7BD74F-2B8D-469E-DFF7-EC6BF4D5FA7D}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.mygeek/index.phtml';
_reg_info['SearchCentrix adware variant']['{CD2A865B-6C0F-44F9-BAA1-7CDB31E04BC8}']['file'] = 'BarBHO.dll';
_reg_info['SearchCentrix adware variant']['{CD2A865B-6C0F-44F9-BAA1-7CDB31E04BC8}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.barbho/index.phtml';
_reg_info['SearchCentrix variant']['{4E7BD74F-2B8D-469E-D9FB-FA6BAD98FA7D}']['file'] = 'MyGeek.dll - MyGeek/Search-o-Matic2000';
_reg_info['SearchCentrix variant']['{4E7BD74F-2B8D-469E-D9FB-FA6BAD98FA7D}']['url'] = 'http://www.kephyr.com/spywarescanner/library/searchcentrix.mygeek/index.phtml';
_reg_info['SearchEnhancement hijacker']['{00041A26-7033-432C-94C7-6371DE343822}']['file'] = 'scbar.dll';
_reg_info['SearchEnhancement hijacker']['{22941A26-7033-432C-94C7-6371DE343822}']['file'] = 'Scbar.dll';
_reg_info['SearchEx']['{1A98BCA2-0BD1-47DE-9710-C7665F7F1FCB}']['file'] = 'Iebrw.dll';
_reg_info['Searchex']['{A116A5C1-AD77-446C-992A-F56200B112DB}']['file'] = 'Homepage.dll';
_reg_info['Searchex']['{B405EE45-1AA2-410D-A6CF-1A74371DCD62}']['file'] = 'Hotlink.dll';
_reg_info['SearchFast parasite']['{000277A3-7D84-406a-9799-D12A81594693}']['file'] = 'srchfst.dll';
_reg_info['SearchFu/123Search']['{A096A159-4E58-45A9-8EE6-B11466851181}']['file'] = 'msietk1020.dll';
_reg_info['searchingall.com/onedollaremail.com pay-per-click foistware']['{88F0297D-A046-4942-B6B9-03D8939E92D5}']['file'] = 'DeskwareDownloader.dll';
_reg_info['SearchMiracle.EliteBar']['{28CAEFF3-0F18-4036-B504-51D73BD81ABC}']['file'] = 'EliteToolBar version 53.dll';
_reg_info['SearchMiracle.EliteBar']['{28CAEFF3-0F18-4036-B504-51D73BD81ABC}']['url'] = 'http://www.sunbeltsecurity.com/ThreatDisplay.aspx?tid=14899&cs=7E9A08E6440BB6B17C339F5DC5C816FA';
_reg_info['SearchMiracle.EliteBar']['{ED103D9F-3070-4580-AB1E-E5C179C1AE41}']['file'] = 'EliteSideBar';
_reg_info['SearchMiracle.EliteBar']['{ED103D9F-3070-4580-AB1E-E5C179C1AE41}']['url'] = 'http://www.sunbeltsecurity.com/ThreatDisplay.aspx?tid=14899&cs=7E9A08E6440BB6B17C339F5DC5C816FA';
_reg_info['Searchportal.info - CoolWebSearch parasite variant']['{28F65FCB-D130-11D8-BA48-8BE0C49AF370}']['file'] = 'popup_bl.dll';
_reg_info['Searchportal.info - CoolWebSearch parasite variant']['{28F65FCB-D130-11D8-BA48-8BE0C49AF370}']['url'] = 'http://www.merijn.nu/programs.php#cwshredder';
_reg_info['SearchSquire']['{11990E9F-2A4D-11D6-9507-02608CDD2842}']['file'] = 'SearchSquire.dll';
_reg_info['SearchSquire']['{907CA0E5-CE84-11D6-9508-02608CDD2841}']['file'] = 'SEARCH~2.DLL';
_reg_info['SearchSquire']['{907CA0E5-CE84-11D6-9508-02608CDD2842}']['file'] = 'SearchSquire2.dll';
_reg_info['SearchSquire']['{907CA0E5-CE84-11D6-9508-02608CDD2846}']['file'] = 'SearchUpdate33.dll';
_reg_info['SecondPower Multimedia Speedbar']['{D985E70B-97F1-477E-AF6C-66E496DEDBD6}']['file'] = '2ndpower.dll';
_reg_info['SecondPower Multimedia Speedbar']['{D985E70B-97F1-477E-AF6C-66E496DEDBD6}']['url'] = 'http://web.archive.org/web/20041009192458/http://support.microsoft.com/default.aspx?kbid=320159';
_reg_info['SeekSeek']['{5074851C-F67A-488E-A9C9-C244573F4068}']['file'] = 'iesearch.dll';
_reg_info['SeekSeek']['{5074851C-F67A-488E-A9C9-C244573F4068}']['url'] = 'http://www.trendmicro.com/vinfo/virusencyclo/default5.asp?VName=ADW_SCANPORTAL.A&VSect=T';
_reg_info['Sexxxpassport.com browser plugin']['{0A7E7249-89E4-4FBF-B256-04DC8F8BAD69}']['file'] = 'Spp3.dll';
_reg_info['Sexxxpassport.com browser plugin']['{11904CE8-632A-4856-A7CC-00B33FE71BD8}']['file'] = 'Spp3.dll';
_reg_info['ShopForGood/Marketdart']['{05BBB56A-2A69-4A5C-BFDA-43295DD67434}']['file'] = 'Winy.dll';
_reg_info['ShopForGood/Marketdart']['{05BBB56A-2A69-4A5C-BFDA-43295DD67434}']['url'] = 'http://www.kephyr.com/spywarescanner/library/shopforgood/index.phtml';
_reg_info['ShopNav variant']['{0007522A-2297-43C1-8EB1-C90B0FF20DA5}']['file'] = 'enhtb.dll';
_reg_info['ShopNavSearch/Srng']['{14B3D246-6274-40B5-8D50-6C2ADE2AB29B}']['file'] = 'Snhelper.dll';
_reg_info['ShopNavSearch/Srng']['{CE7C3CF0-4B15-11D1-ABED-709549C10000}']['file'] = 'Iehelper.dll';
_reg_info['SideSearch variant']['{C5183ABC-EB6E-4E05-B8C9-500A16B6CF94}']['file'] = 'sep.dll';
_reg_info['SideSearch']['{00000762-3965-4A1A-98CE-3D4BF457D4C8}']['file'] = 'sidesearch.dll';
_reg_info['SideStep']['{08351226-6472-43BD-8A40-D9221FF1C4CE}']['file'] = 'SbCIe026.dll';
_reg_info['SideStep']['{08351227-6472-43BD-8A40-D9221FF1C4CE}']['file'] = 'SbCIe027.dll';
_reg_info['SideStep']['{D714A94F-123A-45CC-8F03-040BCAF82AD6}']['file'] = 'SbCIe028.dll';
_reg_info['SmartBrowser']['{00000185-B716-11D3-92F3-00D0B709A7D8}']['file'] = 'BHO.0.1.0';
_reg_info['SmartBrowser']['{00000185-C745-43D2-44F1-01A1C789C738}']['file'] = 'BHO.0.1.0';
_reg_info['SmartPops']['{0421701D-CF13-4E70-ADF0-45A953E7CB8B}']['file'] = 'RH.dll';
_reg_info['SmartPops']['{0421701D-CF13-4E70-ADF0-45A953E7CB8B}']['url'] = 'http://www.kephyr.com/spywarescanner/library/smartpops/index.phtml';
_reg_info['SmartPops']['{D5C778F1-CF13-4E70-ADF0-45A953E7CB8B}']['file'] = 'Ne.dll';
_reg_info['SmartPops']['{D5C778F1-CF13-4E70-ADF0-45A953E7CB8B}']['url'] = 'http://www.kephyr.com/spywarescanner/library/smartpops/index.phtml';
_reg_info['SmartShopper']['{2A8A997F-BB9F-48F6-AA2B-2762D50F9289}']['file'] = 'smrtshpr.dll';
_reg_info['SpiderSearch, iLookup parasite variant']['{EB386233-65D7-46DC-A73D-0E02F2F844A9}']['file'] = 'winsps32.dll';
_reg_info['SpiderSearch, iLookup variant']['{1D022C27-3771-4D1D-B1B7-1953E271C6CA}']['file'] = 'winsps32.dll';
_reg_info['Spyware.BrowserAccel']['{074E3AA7-7718-4404-B3F8-FF8FB5414E0E}']['file'] = 'BrowserAccelerator.dll';
_reg_info['Spyware.BrowserAccel']['{074E3AA7-7718-4404-B3F8-FF8FB5414E0E}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/spyware.browseraccel.html';
_reg_info['Spyware.DigitalNames variant']['{183D5161-0C62-4295-896C-44E7442CD6F2}']['file'] = 'DigitalNamesPlugIn150.dll';
_reg_info['Spyware.DigitalNames variant']['{183D5161-0C62-4295-896C-44E7442CD6F2}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/spyware.digitalnames.html';
_reg_info['Spyware.DigitalNames']['{C18517DA-CA70-46CE-86F4-882F6B62E975}']['file'] = 'bms.dll';
_reg_info['Spyware.DigitalNames']['{C18517DA-CA70-46CE-86F4-882F6B62E975}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/spyware.digitalnames.html';
_reg_info['SRNG/ShopNav']['{4E7BD74F-2B8D-469E-C0FB-EF60B19DB42E}']['file'] = 'SNHelper.dll';
_reg_info['StartNow/HyperBar']['{4B2F5308-2CB0-40E2-8030-59936ED5D22C}']['file'] = 'Hyperbar.dll';
_reg_info['StartNow/HyperBar']['{4B2F5308-2CB0-40E2-8030-59936ED5D22C}']['url'] = 'http://www.bleepingcomputer.com/forums/topic106283.html';
_reg_info['StickyPops.com adware']['{06594350-D723-11D8-9669-0800200C9A66}']['file'] = 'DNSProxy.dll';
_reg_info['StickyPops.com adware']['{1433F750-E53F-11D8-9669-0800200C9A66}']['file'] = 'STRAd32.dll';
_reg_info['StickyPops.com adware']['{FF4E2C50-BCF3-47cf-952A-A512F5B5D0E8}']['file'] = 'DNSProxy.dll';
_reg_info['Stingware GuardBar']['{62F5BBB6-A71E-46E7-AE78-73D25185EDC8}']['file'] = 'GuardBar.dll';
_reg_info['SubmitHook']['{2E9CAFF6-30C7-4208-8807-E79D4EC6F806}']['file'] = 'Submithook.dll';
_reg_info['SubSearch v22']['{1D870C86-AA3C-4451-81E4-71D480A1A652}']['file'] = 'SbSrch_V22.dll';
_reg_info['SubSearch v22']['{31995C64-CB4D-483E-82C2-CCFFE2F66CAB}']['file'] = 'msvcn.dll';
_reg_info['SubSearch']['{4C4871FD-30F6-4430-8834-BC75D58F1529}']['file'] = 'Sbsrch_v2.dll';
_reg_info['SubSearch']['{90DA654C-083C-11D6-8A9D-0050BA8452C0}']['file'] = 'sbsrch_v2.dll';
_reg_info['Subsearch']['{D9A5A49C-60EB-4C07-8570-8FB8FE825E7C}']['file'] = 'sbsrch_v2.dll';
_reg_info['SuperBar']['{136A9D1D-1F4B-43D4-8359-6F2382449255}']['file'] = 'Superbar.dll';
_reg_info['Superlogy.com hijacker']['{95E02C52-05FC-425D-8378-9DA70F9CD763}']['file'] = 'Aadl.dll';
_reg_info['Superlogy.com search hijacker']['{08227B4B-54FE-4C4D-809F-BCA46292FC5B}']['file'] = 'Zedd4.dll';
_reg_info['SurfSideKick adware']['{CA0E28FA-1AFD-4C21-A8DC-70EB5BE2F076}']['file'] = 'SskBho.dll';
_reg_info['SurfSideKick adware']['{CA0E28FA-1AFD-4C21-A8DC-70EB5BE2F076}']['url'] = 'http://www.symantec.com/security_response/writeup.jsp?docid=2004-112118-0309-99';
_reg_info['suspected keyword hijacker']['{6D9F42B8-B7E5-4BB9-9A13-CAE53D44196E}']['file'] = 'searcher.dll';
_reg_info['suspected keyword hijacker']['{6D9F42B8-B7E5-4BB9-9A13-CAE53D44196E}']['url'] = 'http://www.kephyr.com/spywarescanner/library/browseraid/index.phtml';
_reg_info['System61 hijacker']['{C7967580-5F17-11D4-AAC2-0000B4936E0C}']['file'] = 'System61.dll';
_reg_info['t2t2.com toolbar by Chengwei Ventures LLC']['{B1D147E7-873E-4909-8127-695D9BB78728}']['file'] = 'barhelp.dll';
_reg_info['Thesearchmall, iLookup variant']['{0AEE4D0C-4B38-4196-AE32-70ACE5656647}']['file'] = 'winsrm32.dll';
_reg_info['ToolbarCC/Rnd']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFA7}']['file'] = 'win';
_reg_info['ToolbarCC/Rnd']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFA8}']['file'] = 'win';
_reg_info['ToolbarCC/Rnd']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFAF}']['file'] = 'dll';
_reg_info['ToolbarCC']['{1F48AA48-C53A-4E21-85E7-AC7CC6B5FFA2}']['file'] = 'dll';
_reg_info['Top-banners.com adware']['{968BC8A3-7660-4B12-B2BF-3334775835E1}']['file'] = 'KGhost.dll';
_reg_info['TOPicks']['{0352960F-47BE-11D5-AB93-00D0B760B4EB}']['file'] = 'Htcheck2.dll';
_reg_info['TotalVelocity zSearch']['{5886A6DC-AAF4-45E9-979A-8E5E6DEE30E7}']['file'] = 'zSearch.dll';
_reg_info['Townews.com adware']['{634EFDE4-087D-4ce9-952F-63C9EEB2E0BF}']['file'] = 'WNDPOS~1.DLL';
_reg_info['TrafficHog, iLookup variant']['{086CEFD5-A88D-4981-8915-D51F04360ED1}']['file'] = 'winalot32.dll';
_reg_info['Traffix Inc/iMatchup']['{3F68A524-6E47-44E6-9FE7-795EABFA3B36}']['file'] = 'traffix1.1.0.25.dll';
_reg_info['Transponder parasite variant']['{00000000-C1EC-0345-6EC2-4D0300000000}']['file'] = 'ZServ.dll';
_reg_info['Transponder parasite variant']['{00000250-0320-4DD4-BE4F-7566D2314352}']['file'] = 'VoiceIP.dll';
_reg_info['Transponder parasite variant']['{00320615-B6C2-40A6-8F99-F1C52D674FAD}']['file'] = 'localNRD.dll';
_reg_info['Transponder variant']['{00000000-F09C-02B4-6EC2-AD0300000000}']['file'] = 'BTGrab.dll';
_reg_info['Transponder']['{0000026A-8230-4DD4-BE4F-6889D1E74167}']['file'] = 'Tps108.dll';
_reg_info['Transponder']['{00000273-8230-4DD4-BE4F-6889D1E74167}']['file'] = 'host.dll';
_reg_info['Troj/Bamer-B']['{C41A1C0E-EA6C-11D4-B1B8-444553540000}']['file'] = 'rundll32.dll';
_reg_info['Troj/Bdoor-CLS']['{A452DA63-4286-48EB-A838-3BA85C3049F5}']['file'] = 'Acrobat.dll';
_reg_info['Troj/StartPa-DW hijacker variant']['{B72F75B8-93F3-429D-B13E-660B206D897A}']['file'] = 'beem.dll';
_reg_info['TROJ_DELF.CR trojan']['{D8569837-3CD6-4AD7-9A77-65975B581925}']['file'] = 'dll';
_reg_info['Trojan FAVADD.C']['{CE7C3CF0-4B15-11D1-ABED-709549C10020}']['file'] = 'random named';
_reg_info['Trojan.Clicker.Delf.ai']['{08DF42F3-792D-4944-941B-512582B87219}']['file'] = 'adobeacr.dll';
_reg_info['Trojan.Clicker.Delf.ai']['{08DF42F3-792D-4944-941B-512582B87219}']['url'] = 'http://research.sunbelt-software.com/threatdisplay.aspx?threatid=47211';
_reg_info['Trojan.Downloader.Domcom.A']['{031B6D43-CBC4-46A5-8E46-CF8B407C1A33}']['file'] = 'ipreg32.dll';
_reg_info['Trojan.Goldun.B']['{92617934-9abc-def0-0fed-fad48c654321}']['file'] = '';
_reg_info['Trojan.Goldun.B']['{92617934-9abc-def0-0fed-fad48c654321}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.goldun.b.html';
_reg_info['Trojan.Magise']['{A6790AA5-C6C7-4BCF-A46D-0FDAC4EA90EB}']['file'] = 'msearch.dll';
_reg_info['Trojan.Magise']['{A6790AA5-C6C7-4BCF-A46D-0FDAC4EA90EB}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.magise.html';
_reg_info['Trojan.Magise']['{D7BF3304-138B-4DD5-86EE-491BB6A2286C}']['file'] = 'msearch.dll';
_reg_info['Trojan.Magise']['{D7BF3304-138B-4DD5-86EE-491BB6A2286C}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.magise.html';
_reg_info['Trojan.Magise']['{FFF5092F-7172-4018-827B-FA5868FB0478}']['file'] = 'msearch.dll';
_reg_info['Trojan.Magise']['{FFF5092F-7172-4018-827B-FA5868FB0478}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.magise.html';
_reg_info['Trojan.Win32.Delf.cf']['{E412F14A-E998-4543-9E7A-1031A3189A87}']['file'] = 'dll';
_reg_info['Trojan-Clicker.Win32.Delf.bc']['{4E7BD74F-2B8D-469E-85AC-FD60BB9AAE32}']['file'] = 'seotoolbar.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{9EAC0102-5E61-2312-BC2D-414456544F4E}']['file'] = 'ADV.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{9EAC0102-5E61-2312-BC2D-444C4C4F5552}']['file'] = 'DLL.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{9EAC0102-5E61-2312-BC2D-4D54434D5443}']['file'] = 'mtc.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{9EAC0102-5E61-2312-BC2D-4E4153202020}']['file'] = 'NAS.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{9EAC0102-5E61-2312-BC2D-544243544243}']['file'] = 'TBC.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{9EAC0102-5E61-2312-BC2D-76746C56544C}']['file'] = 'vtlbar1.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-716D61788264}']['file'] = 'max8264.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-716D74632608}']['file'] = 'mtc2608.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717177650486}']['file'] = 'QWE0486.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717177654820}']['file'] = 'qwe4820.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717177657972}']['file'] = 'qwe7972.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717177658264}']['file'] = 'max8264.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-7173706D1316}']['file'] = 'spm1316.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-7173706D4820}']['file'] = 'spm4820.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717765721306}']['file'] = 'wer1306.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717765721316}']['file'] = 'wer1316.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717765724820}']['file'] = 'wer4820.dll';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717965725750}']['file'] = 'yer5750';
_reg_info['Tubby/MakeMeSearch/Spyware.Arau parasite']['{CF021F40-3E14-23A5-CBA2-717965726032}']['file'] = 'yer6032.dll';
_reg_info['TV Media/CleverIEHooker']['{707E6F76-9FFB-4920-A976-EA101271BC25}']['file'] = 'Jeired.dll';
_reg_info['TwainTech adware']['{000020DD-C72E-4113-AF77-DD56626C6C42}']['file'] = 'twaintec.dll';
_reg_info['TwainTech adware']['{000020DD-C72E-4113-AF77-DD56626C6C42}']['url'] = 'http://www.pchell.com/support/twaintec.shtml';
_reg_info['TwainTech adware']['{0000607D-D204-42C7-8E46-216055BF9918}']['file'] = 'mxTarget.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0000-5DFC-5652-1705043F6518}']['file'] = 'audiosrv32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0000-7EBF-57C6-0BAE047EA682}']['file'] = 'autodisc32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0001-0345-2280-0287F27A63EE}']['file'] = 'Browserad.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0001-1DBE-075A-39EC04BD88AF}']['file'] = 'Avicap32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0001-F7A6-1F38-0204019E355E}']['file'] = 'Asferror32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0002-53D4-0622-35EA0235778E}']['file'] = 'Ati2dvaa32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0008-D357-0798-004401965D4A}']['file'] = 'apphelp32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0009-1C42-7D61-6CFF050894A7}']['file'] = 'avisynthEx32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0015-BD9C-263A-493001BA0C6C}']['file'] = 'asycfilt32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-002B-EFE6-6B08-560C01922D3B}']['file'] = 'Apcups32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0033-C1AC-0E62-0C1F0537605D}']['file'] = 'aviwrap32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-008C-1E65-6AA6-3A270279F027}']['file'] = 'Ati2dvag32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-00FA-71ED-4ABA-348801BAA0A9}']['file'] = 'Athprxy32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-08C8-8E68-587B-61F804EE6164}']['file'] = 'avisynth32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-0C95-B1F8-547A-405204D6961A}']['file'] = 'avifile32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-1530-70F0-6420-4C2701B37263}']['file'] = 'asfsipc32.dll';
_reg_info['TX 4 BrowserAd adware']['{00000000-387E-9D50-0079-1744044CB22A}']['file'] = 'authz32.dll';
_reg_info['UCmore toolbar']['{ED8DB0FD-D8F4-4b2c-BB5B-9EF040FE104D}']['file'] = 'Ucmie.dll';
_reg_info['unidentified adware']['{1E1B2879-88FF-11D2-8D96-D7ACAC31337F}']['file'] = 'Mslink32.dll';
_reg_info['Unidentified adware']['{E155EDD6-FA1E-4876-8FB2-5FB358014EBE}']['file'] = 'sequitur1b.dll';
_reg_info['unidentified hijacker']['{044D9F9F-0EE0-4E9B-B89B-5EBCA0F852CC}']['file'] = 'fsearchbar.dll';
_reg_info['unidentified hijacker']['{29A38549-AF6F-11D4-89D6-BC1DFD912B00}']['file'] = 'bho1.dll';
_reg_info['Unidentified hijacker']['{D879A0F1-2B3B-4409-8879-FAD6E49E1EA9}']['file'] = 'mshtmpre.dll';
_reg_info['Unidentified malware']['{D8FF9A84-FEB9-4B4B-B36B-D46570203C39}']['file'] = 'key.dll';
_reg_info['Unknown Adware']['{C003C49F-53E4-4A72-B7D6-0B2B9997392F}']['file'] = 'webdir.dll';
_reg_info['Unknown Adware']['{C003C49F-53E4-4A72-B7D6-0B2B9997392F}']['url'] = 'http://www.superadblocker.com/spywaredisplay.html?id=1281';
_reg_info['unknown malware']['{01FB9C55-FC66-4476-A199-389241193188}']['file'] = 'dll';
_reg_info['unknown malware']['{01FB9C55-FC66-4476-A199-389241193188}']['url'] = 'http://www.virit.com/startup/scheda.asp?num=21';
_reg_info['URLBlaze']['{CE7C3CF0-4B15-11D1-ABED-709549C10000}']['file'] = 'Ubmon.dll';
_reg_info['URLBlaze']['{CE7C3CF0-4B15-11D1-ABED-709549C10000}']['url'] = 'http://www.urlblaze.com';
_reg_info['VirtuMonde adware variant Vundo']['{02F96FB7-8AF6-439B-B7BA-2F952F9E4800}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant Vundo']['{02F96FB7-8AF6-439B-B7BA-2F952F9E4800}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/trojan.vundo.html';
_reg_info['VirtuMonde adware variant']['{18722863-6D1D-4300-BF29-406948EDA7CB}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{18722863-6D1D-4300-BF29-406948EDA7CB}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{2316230A-C89C-4BCC-95C2-66659AC7A775}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{2316230A-C89C-4BCC-95C2-66659AC7A775}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{30279F2D-1A38-4785-97D4-5C3508BDB289}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{30279F2D-1A38-4785-97D4-5C3508BDB289}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{3EC8E271-FAB9-418a-8A8E-65AEB4029E64}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{3EC8E271-FAB9-418a-8A8E-65AEB4029E64}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{446CF8A5-617E-4D91-95AE-AE78CE0D06AF}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{446CF8A5-617E-4D91-95AE-AE78CE0D06AF}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{44E5B409-35A2-4E8D-BF94-344222323A53}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{44E5B409-35A2-4E8D-BF94-344222323A53}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{55E301E5-BA44-4095-BB0B-14E0123CCF71}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{55E301E5-BA44-4095-BB0B-14E0123CCF71}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{60112085-E1CE-4e0e-823A-EBB1AD98804C}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{60112085-E1CE-4e0e-823A-EBB1AD98804C}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{68132581-10F2-416E-B188-4E648075325A}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{68132581-10F2-416E-B188-4E648075325A}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{6A06CDAD-9D2D-42A0-9C91-C0CF7CB9971B}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{6A06CDAD-9D2D-42A0-9C91-C0CF7CB9971B}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{72AC6865-B1D3-4C32-A27B-4B3BF04DE655}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{72AC6865-B1D3-4C32-A27B-4B3BF04DE655}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{73529697-D46A-4F7D-8A93-01378FCAEDA4}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{73529697-D46A-4F7D-8A93-01378FCAEDA4}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{77849D67-5672-4B68-93E2-CCEFF1E3949E}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{77849D67-5672-4B68-93E2-CCEFF1E3949E}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{8109AF33-6949-4833-8881-43DCC232B7B2}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{8109AF33-6949-4833-8881-43DCC232B7B2}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{870B70D4-F6DA-47AE-9158-D146440A0A4D}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{870B70D4-F6DA-47AE-9158-D146440A0A4D}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{BF755B85-EA69-4F58-9A59-D85F384A15FF}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{BF755B85-EA69-4F58-9A59-D85F384A15FF}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{C69FA570-7FDE-4C49-A7BC-CB1CF24BE66B}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{C69FA570-7FDE-4C49-A7BC-CB1CF24BE66B}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{D6964FD8-3AF1-4A2A-ABB7-3D0C62924FD6}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{D6964FD8-3AF1-4A2A-ABB7-3D0C62924FD6}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{DF57FEB6-9BCE-45E3-AA65-BE327B8CCE7F}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{DF57FEB6-9BCE-45E3-AA65-BE327B8CCE7F}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{ED5ABC42-8E4F-4C39-9972-F0CF619D672F}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{ED5ABC42-8E4F-4C39-9972-F0CF619D672F}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{F32F8ECD-6CF3-459D-82F2-9738392C85A8}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{F32F8ECD-6CF3-459D-82F2-9738392C85A8}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['VirtuMonde adware variant']['{FD8609EC-7D7C-4778-AB8F-0053245550EF}']['file'] = 'dat';
_reg_info['VirtuMonde adware variant']['{FD8609EC-7D7C-4778-AB8F-0053245550EF}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/adware.virtumonde.html';
_reg_info['Vividence Connector']['{C3BCC488-1AE7-11D4-AB82-0010A4EC2338}']['file'] = 'hoproxy.dll';
_reg_info['Vividence Connector']['{C3BCC488-1AE7-11D4-AB82-0010A4EC2338}']['url'] = 'http://web.archive.org/web/20040221173855/http://www.vividence.com/public/products/vividence+xms+enterprise/vividence+xms+enterprise/connector.htm';
_reg_info['Voonda Toolbar']['{4E7BD74F-2B8D-469E-D4FF-EB2CF4D5FA7D}']['file'] = 'taf.dll';
_reg_info['VX2 Respondmiter, Blackstone Transponder']['{00000000-5eb9-11d5-9d45-009027c14662}']['file'] = 'ehelper.dll';
_reg_info['VX2 Transponder variant']['{00000580-C637-11D5-831C-00105AD6ACF0}']['file'] = 'Msview.dll';
_reg_info['VX2 Variant']['{FFD2825E-0785-40C5-9A41-518F53A8261F}']['file'] = 'SiteHlpr.dll';
_reg_info['VX2.aBetterInternet variant']['{2DC9D850-144D-11E1-B3C9-10805E499D95}']['file'] = 'mplay32.dll';
_reg_info['VX2.aBetterInternet']['{000006B1-19B5-414A-849F-2A3C64AE6939}']['file'] = 'bi.dll';
_reg_info['W32.Aspam.Trojan.B']['{499DB658-1909-420B-931A-4A8CAEFD232F}']['file'] = 'Drvman32.dll';
_reg_info['W32.Aspam.Trojan.B']['{499DB658-1909-420B-931A-4A8CAEFD232F}']['url'] = 'http://securityresponse.symantec.com/avcenter/venc/data/w32.aspam.trojan.b.html';
_reg_info['Webhancer']['{C900B400-CDFE-11D3-976A-00E02913A9E0}']['file'] = 'Whiehlpr.dll';
_reg_info['Webhancer']['{C900B400-CDFE-11D3-976A-00E02913A9E0}']['url'] = 'http://www.cexx.org/webhancer.htm';
_reg_info['WebSearch']['{001DAE60-95C0-11d3-924E-009027950886}']['file'] = 'Spotonbh.dll';
_reg_info['WebSearch']['{001DAE60-95C0-11d3-924E-009027950886}']['url'] = 'http://www.spywareguide.com/product_show.php?id=505';
_reg_info['Whazit']['{10955232-B671-11D7-8066-0040F6F477E4}']['file'] = 'whattn.dll';
_reg_info['Whazit']['{267D5BD3-0DC2-4724-A196-7F4794FBB9EB}']['file'] = 'outones.dll';
_reg_info['Whazit']['{66F67511-2665-4C34-9E20-FAC2C0954EF2}']['file'] = 'whattt.dll';
_reg_info['Whazit']['{D5B72AED-E54A-11D6-B1B2-444553540000}']['file'] = 'Bho.dll';
_reg_info['Whazit']['{D7D7004C-A763-4F8C-B0D4-55A7E017E69D}']['file'] = 'newones.dll';
_reg_info['WhistleSoftware']['{27557cf1-a237-496d-8c8f-08f3844c6a8b}']['file'] = 'WhistleHelper.dll';
_reg_info['WhistleSoftware']['{27557cf1-a237-496d-8c8f-08f3844c6a8b}']['url'] = 'http://web.archive.org/web/20031203044254/http://uslocalweather.com/privacy.asp';
_reg_info['Win32.StartPage.np hijacker']['{CE7C3CF0-4B15-11D1-ABED-709549C10000}']['file'] = 'StopzillaBH0.dll';
_reg_info['Win32/Aspam.Trojan']['{657B9354-BB3B-4500-A9B0-109B4FA64815}']['file'] = 'amcis32.dll';
_reg_info['WinAd']['{53D3C442-8FEE-4784-9A21-6297D39613F0}']['file'] = 'Winad2.dll';
_reg_info['WinAd']['{53D3C442-8FEE-4784-9A21-6297D39613F0}']['url'] = 'http://www.kephyr.com/spywarescanner/library/winad/index.phtml';
_reg_info['Windows Search Bar hijacker']['{9FB534E3-67CB-4307-AE0A-9E8B5581BE2C}']['file'] = 'WinSB.dll';
_reg_info['Winpage Blocker']['{12DF6E3E-6272-4AE8-880B-2158D60791C0}']['file'] = 'WinPage.dll';
_reg_info['Winshow/Searchv.com hijacker']['{6CC1C918-AE8B-4373-A5B4-28BA1851E39A}']['file'] = 'winshow.dll';
_reg_info['Wishbone Toolbar']['{3AA90BC2-58C0-4F4D-A87C-2C6F3D3CD5FE}']['file'] = 'Minst.dll';
_reg_info['Wishbone Toolbar']['{C331BD6E-06AB-41A0-B95F-D7CA379ACEAA}']['file'] = 'WBM.DLL';
_reg_info['WurldMedia/bpboh']['{40AC4D2D-491D-11D4-AAF2-0008C75DCD2B}']['file'] = 'Bpboh.dll';
_reg_info['WurldMedia']['{2737A6C0-7E24-11D7-B299-00E0297E0844}']['file'] = '';
_reg_info['WurldMedia']['{3A279869-C6B6-4410-A041-0435DE6AD916}']['file'] = 'M030106SHOP.DLL';
_reg_info['WurldMedia']['{525BBD23-1863-46C6-86D6-5F9A3715D44E}']['file'] = 'mbho.dll';
_reg_info['WurldMedia']['{5A3A5040-4210-11D7-BD2E-00080E34122F}']['file'] = 'M030206POHS.DLL';
_reg_info['WurldMedia']['{8E9C4F32-BD3F-4C49-9AF5-3F4C5D32EBD7}']['file'] = 'mbho.dll';
_reg_info['WurldMedia']['{98D7B53E-B1D2-4755-B0A4-703E18FF91E8}']['file'] = 'M030106SHOP.DLL';
_reg_info['WurldMedia']['{CDBCFEAE-10BA-482C-9F6E-FC67207082D8}']['file'] = 'mdefshop.dll';
_reg_info['WurldMedia']['{D14641FA-445B-448E-9994-209f7AF15641}']['file'] = 'mbho.dll';
_reg_info['WurldMedia']['{F325E940-45EE-11D7-A420-444553540000}']['file'] = 'M030206POHS.DLL';
_reg_info['WurldMedia']['{F59D88CF-939A-4E50-9587-65A2E22EF077}']['file'] = 'mob030612.dll';
_reg_info['Xlocator/WinLocator adware']['{89AEAB46-8E8A-4045-9003-5614BFBFE90B}']['file'] = 'Winlocatorhelper.dll';
_reg_info['Xlocator/WinLocator adware']['{89AEAB46-8E8A-4045-9003-5614BFBFE90B}']['url'] = 'http://www.kephyr.com/spywarescanner/library/xlocator/index.phtml';
_reg_info['Xpehbam.biz dialer related malware']['{FCADDC14-BD46-408A-9842-111111111111}']['file'] = 'Backup.dll';
_reg_info['Xpehbam.biz dialer related malware']['{FCADDC14-BD46-408A-9842-CDB57890086B}']['file'] = 'Dial.dll';
_reg_info['Xupiter Orbitexplorer']['{702AD576-FDDB-4d0f-9811-A43252064684}']['file'] = 'Toolbar.dll';
_reg_info['Xupiter Orbitexplorer']['{D48F2E28-68E2-4920-9848-D6E6C7AB3EB7}']['file'] = 'Redirector.dll';
_reg_info['Xupiter']['{2662BDD7-05D6-408F-B241-FF98FACE6054}']['file'] = 'Xtupdate.dll';
_reg_info['ZeroPopupBar']['{72A58725-2635-4725-8C53-676DFD1FEB8D}']['file'] = 'zeropopupbar.dll';
_reg_info['Zy web search hijacker']['{06CAD548-14DD-4fa3-9EA9-05F83C18CBD7}']['file'] = 'MSPXS32.DLL';
_reg_info['ZyncosMark']['{F0DC0CFE-D11A-489B-84C0-63748AFAABF3}']['file'] = 'Cmctl.dll';

##
# Returns error code for given template and prints error.
#
# @param  list  error_template defined in header
# @param  list  args
#
# @return int   error corresponding to error_template or IF_ERROR if
#               error occurs within this function
##
function _return_error(error_template, args)
{
  # Allow arguments to be passed anonymously.
  if (isnull(error_template)) error_template = _FCT_ANON_ARGS[0];
  if (isnull(args)) args = _FCT_ANON_ARGS[1];

  # Input validation.
  if (isnull(error_template))
  {
    err_print("return_error(): missing required argument 'error_template'.");
    return SF_ERROR;
  }

  if (isnull(args))
  {
    err_print("return_error(): missing required argument 'args'.");
    return SF_ERROR;
  }

  if (typeof(error_template) != 'array' || len(error_template) != 3)
  {
    err_print("return_error(): An invalid error template was passed.");
    return SF_ERROR;
  }

  if (typeof(args) != 'array' || len(args) != error_template[0])
  {
    err_print("return_error(): The number of args passed does not match the error template for " +
      "error code: " + error_template[2] + ". (Expected " + error_template[0] +
      ", received " + len(args) + ")");
    return SF_ERROR;
  }

  # Print error if verbose.
  if (SF_VERBOSE_ERRORS) err_print(vsprintf(args:args, format:error_template[1]));

  return error_template[2];
}

##
# Adds file information to the report.
# Either the CLSID or file name must be passed.
#
# @param string   name - Name of application
# @param string   clsid - CLSID key
# @param string   file - Name of file found in system root
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the report modifications
#                          (NULL if ret[0] != IF_OK)
##
function _add_to_report(name, clsid, file)
{
  local_var r_file, url, report, args;

  if (isnull(name))
  {
    args = make_list('_add_report', 'name');
    return make_list(_return_error(SF_MISSING_ARG_TEMPLATE, args));
  }

  if (isnull(clsid) && isnull(file))
  {
    args = make_list('_add_report', 'clsid/file');
    return make_list(_return_error(SF_MISSING_ARG_TEMPLATE, args));
  }

  if(empty_or_null(Report))
  {
    report = '\n  Make sure the user of the remote host intended to install the following' +
             '\n  software, and that its use matches your corporate security policy.\n';
  }
  else
    report += '\n';

  report += '\n  Name  : ' + name;

  if(!empty_or_null(clsid))
  {
    report += '\n  CLSID : ' + clsid;

    r_file = _reg_info[name][clsid]['file'];
    url = _reg_info[name][clsid]['url'];

    if(!empty_or_null(r_file))
      report += '\n  File  : ' + r_file;

    if(!empty_or_null(url))
      report += '\n  URL   : ' + url;
  }
  else
  {
    if(isnull(Sys_root))
    {
      args = make_list('_add_report', 'Sys_root');
      return make_list(_return_error(SF_UNEXPECTED_NULL_TEMPLATE, args));
    }

    report += '\n  File  : ' + Sys_root + "\" + file;

    url = _file_info[name][file];

    if(!empty_or_null(url))
      report += '\n  URL   : ' + url;
  }

  Report += report;

  return make_list(SF_OK, report);
}

##
# Checks the registry for suspicious CLSIDs
#
# @return return code
##
function check_reg_clsids()
{
  local_var name, clsid, file, count;
  local_var url, c_name, ret, args;

  count = 0;

  if(isnull(_reg_info))
  {
    args = make_list('check_reg_clsids', '_reg_info');
    return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
  }

  if (com_init() != 0)
  {
    args = make_list('check_reg_clsids');
    return _return_error(SF_COM_FAIL_TEMPLATE, args);
  }

  foreach name (keys(_reg_info))
  {
    if(isnull(name))
    {
      com_end();
      args = make_list('check_reg_clsids', 'name');
      return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
    }

    foreach clsid (keys(_reg_info[name]))
    {
      if(isnull(clsid))
      {
        com_end();
        args = make_list('check_reg_clsids', 'clsid');
        return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
      }

      if(!com_is_installed(clsid: clsid)) continue;

      file = _reg_info[name][clsid]['file'];

      if(empty_or_null(file))
      {
        ret = _add_to_report(name: name, clsid: clsid);

        if(ret[0] != SF_OK)
        {
          com_end();
          return _return_error(SF_ERROR_TEMPLATE, make_list('check_reg_clsids'));
        }

        continue;
      }

      c_name = com_get_filename(clsid: clsid);

      if(isnull(c_name)) continue;

      if(tolower(file) >< tolower(c_name))
        ret = _add_to_report(name: name, clsid: clsid);

      if(ret[0] != SF_OK)
      {
        com_end();
        return _return_error(SF_ERROR_TEMPLATE, make_list('check_reg_clsids'));
      }
    }
  }

  com_end();

  return SF_OK;
}

##
# Checks the system root for suspicious files
#
# @return return code
##
function check_root_files()
{
  local_var name, file, url, args, ret;

  if(isnull(_file_info))
  {
    args = make_list('check_root_files', '_file_info');
    return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
  }

  Sys_root = hotfix_get_systemroot();

  if(isnull(Sys_root))
  {
    args = make_list('check_root_files', 'Sys_root');
    return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
  }

  hotfix_check_fversion_init();

  foreach name (keys(_file_info))
  {
    if(isnull(name))
    {
      hotfix_check_fversion_end();
      args = make_list('check_reg_clsids', 'name');
      return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
    }

    foreach file (keys(_file_info[name]))
    {
      if(isnull(file))
      {
        hotfix_check_fversion_end();
        args = make_list('check_reg_clsids', 'file');
        return _return_error(SF_UNEXPECTED_NULL_TEMPLATE, args);
      }

      if(hotfix_file_exists(path: Sys_root + "\" + file))
        ret = _add_to_report(name: name, file: file);

      if(ret[0] != SF_OK)
      {
        hotfix_check_fversion_end();
        return _return_error(SF_ERROR_TEMPLATE, make_list('check_reg_clsids'));
      }
    }
  }

  hotfix_check_fversion_end();

  return SF_OK;
}

##
# Returns the final report
#
# @return list s.t. ret[0] is the return code and
#                   ret[1] is a string containing the report modifications
#                          (NULL if ret[0] != IF_OK)
##
function get_report()
{
  if(empty(Report))
    return make_list(SF_EMPTY_REPORT);
  else
    return make_list(SF_OK, Report);
}

##
# Test iterates over all of the files
#
# The registry and file info is outputed to stdout
##
function _test_data()
{
  local_var name, file, r_count, f_count;
  local_var f_name, url, clsid;

  r_count = 0;
  f_count = 0;

  foreach name (keys(_reg_info))
  {
    foreach clsid (keys(_reg_info[name]))
    {
      r_count++;

      display('Name  : ' + name + '\n');
      display('CLSID : ' + clsid + '\n');

      f_name = _reg_info[name][clsid]['file'];
      url = _reg_info[name][clsid]['url'];

      if(!empty_or_null(f_name))
        display('File  : ' + f_name + '\n');

      if(!empty_or_null(url))
        display('URL   : ' + url + '\n');

      display('\n');
    }
  }

  foreach name (keys(_file_info))
  {
    foreach file (keys(_file_info[name]))
    {
      f_count++;

      display('Name : ' + name + '\n');
      display('File : ' + file + '\n');

      url = _file_info[name][file];

      if(!empty_or_null(url))
        display('URL  : ' + url + '\n');

      display('\n');
    }
  }

  display('Reg Count  : ' + r_count + '\n');
  display('File Count : ' + f_count + '\n');
}
