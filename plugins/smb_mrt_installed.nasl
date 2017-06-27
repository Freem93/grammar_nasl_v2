#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(66424);
  script_version("$Revision: 1.52 $");
  script_cvs_date("$Date: 2017/05/10 01:43:15 $");

  script_name(english:"Microsoft Malicious Software Removal Tool Installed");
  script_summary(english:"Checks if MRT is installed.");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An antimalware application is installed on the remote Windows host."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The Microsoft Malicious Software Removal Tool is installed on the
remote host. This tool is an application that attempts to detect and
remove known malware from Windows systems."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.microsoft.com/security/pc-security/malware-removal.aspx");
  script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/891716");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2013/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:malicious_software_removal_tool");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

root = hotfix_get_systemroot();
if (!root)
  audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
version_guid = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\RemovalTools\MRT\Version");
dont_report_to_ms = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\MRT\DontReportInfectionInformation");
RegCloseKey(handle:hklm);

if (isnull(version_guid))
{
  close_registry(close:FALSE);
  audit(AUDIT_NOT_INST, 'MRT');
}
else
{
  version_guid = toupper(version_guid);
  set_kb_item(name:'SMB/MRT/VersionGUID', value:version_guid);
  close_registry(close:FALSE);
}

if (root[strlen(root) - 1] != "\") # add a trailing backslash if necessary
  root += "\";
exe = root + "system32\MRT.exe";

ver = hotfix_get_fversion(path:exe);
hotfix_check_fversion_end();

if (ver['error'] == HCF_NOENT)
  audit(AUDIT_UNINST, 'MRT');
else if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, exe);
version = join(ver['value'], sep:'.');
set_kb_item(name:'SMB/MRT/Version', value:version);

# microsoft keeps a mapping of Version GUIDs to versions at
# http://support.microsoft.com/kb/891716
version_table = make_array(
  'E5DD9936-C147-4CD1-86D3-FED80FAADA6C', 'January 2005',
  '805647C6-E5ED-4F07-9E21-327592D40E83', 'February 2005',
  'F8327EEF-52AA-439A-9950-CE33CF0D4FDD', 'March 2005',
  'D89EBFD1-262C-4990-9927-5185FED1F261', 'April 2005',
  '08112F4F-11BF-4129-A90A-9C8DD0104005', 'May 2005',
  '63C08887-00BE-4C9B-9EFC-4B9407EF0C4C', 'June 2005',
  '2EEAB848-93EB-46AE-A3BF-9F1A55F54833', 'July 2005',
  '3752278B-57D3-4D44-8F30-A98F957EC3C8', 'August 2005',
  '4066DA74-2DDE-4752-8186-101A7C543C5F', 'August 2005 A',
  '33B662A4-4514-4581-8DD7-544021441C89', 'September 2005',
  '08FFB7EB-5453-4563-A016-7DBC4FED4935', 'October 2005',
  '1F5BA617-240A-42FF-BE3B-14B88D004E43', 'November 2005',
  'F8FEC144-AA00-48B8-9910-C2AE9CCE014A', 'December 2005',
  '250985EE-62E6-4560-B141-997FC6377FE2', 'January 2006',
  '99CB494B-98BF-4814-BFF0-CF551AC8E205', 'February 2006',
  'B5784F56-32CA-4756-A521-CA57816391CA', 'March 2006',
  'D0F3EA76-76C8-4287-8CDF-BDFEE5E446EC', 'April 2006',
  'CE818D5B-8A25-47C0-A9CD-7169DA3F9B99', 'May 2006',
  '7CF4B321-C0DD-42D9-AFDF-EDBB85E59767', 'June 2006',
  '5DF61377-4916-440F-B23F-321933B0AFD3', 'July 2006',
  '37949D24-63F1-4FDC-AD24-5DC3EB3AD265', 'August 2006',
  'AC3FA517-20F0-4A42-95CA-6383F04773C8', 'September 2006',
  '79E385D0-5D28-4743-AEB3-ED101C828ABD', 'October 2006',
  '1D21FA19-C296-4020-A7C2-C5A9BA4F2356', 'November 2006',
  '621498CA-889B-48EF-872B-84B519365C76', 'December 2006',
  '2F9BC264-1980-42B6-9EE3-2BE36088BB57', 'January 2007',
  'FFCBCFA5-4EA1-4D66-A3DC-224C8006ACAE', 'February 2007',
  '5ABA0A63-8B4C-4197-A6AB-A1035539234D', 'March 2007',
  '57FA0F48-B94C-49EA-894B-10FDA39A7A64', 'April 2007',
  '15D8C246-6090-450F-8261-4BA8CA012D3C', 'May 2007',
  '234C3382-3B87-41CA-98D1-277C2F5161CC', 'June 2007',
  '4AD02E69-ACFE-475C-9106-8FB3D3695CF8', 'July 2007',
  '0CEFC17E-9325-4810-A979-159E53529F47', 'August 2007',
  'A72DDD48-8356-4D06-A8E0-8D9C24A20A9A', 'September 2007',
  '52168AD3-127E-416C-B7F6-068D1254C3A4', 'October 2007',
  'EFC91BC1-FD0D-42EE-AA86-62F59254147F', 'November 2007',
  '73D860EC-4829-44DD-A064-2E36FCC21D40', 'December 2007',
  '330FCFD4-F1AA-41D3-B2DC-127E699EEF7D', 'January 2008',
  '0E918EC4-EE5F-4118-866A-93F32EC73ED6', 'February 2008',
  '24A92A45-15B3-412D-9088-A3226987A476', 'March 2008',
  'F01687B5-E3A4-4EB6-B4F7-37D8F7E173FA', 'April 2008',
  '0A1A070A-25AA-4482-85DD-DF69FF53DF37', 'May 2008',
  '0D9785CC-AEEC-49F7-81A8-07B225E890F1', 'June 2008',
  'BC308029-4E38-4D89-85C0-8A04FC9AD976', 'July 2008',
  'F3889559-68D7-4AFB-835E-E7A82E4CE818', 'August 2008',
  '7974CF06-BE58-43D5-B635-974BD92029E2', 'September 2008',
  '131437DE-87D3-4801-96F0-A2CB7EB98572', 'October 2008',
  'F036AE17-CD74-4FA5-81FC-4FA4EC826837', 'November 2008',
  '9BF57AAA-6CE6-4FC4-AEC7-1B288F067467', 'December 2008',
  '9BF57AAA-6CE6-4FC4-AEC7-1B288F067467', 'December 2008',
  '2B730A83-F3A6-44F5-83FF-D9F51AF84EA0', 'January 2009',
  'C5E3D402-61D9-4DDF-A8F5-0685FA165CE8', 'February 2009',
  'BDEB63D0-4CEC-4D5B-A360-FB1985418E61', 'March 2009',
  '276F1693-D132-44EF-911B-3327198F838B', 'April 2009',
  'AC36AF73-B1E8-4CC1-9FF3-5A52ABB90F96', 'May 2009',
  '8BD71447-AAE4-4B46-B652-484001424290', 'June 2009',
  'F530D09B-F688-43D1-A3D5-49DC1A8C9AF0', 'July 2009',
  '91590177-69E5-4651-854D-9C95935867CE', 'August 2009',
  'B279661B-5861-4315-ABE9-92A3E26C1FF4', 'September 2009',
  '4C64200A-6786-490B-9A0C-DEF64AA03934', 'October 2009',
  '78070A38-A2A9-44CE-BAB1-304D4BA06F49', 'November 2009',
  'A9A7C96D-908E-413C-A540-C43C47941BE4', 'December 2009',
  'ED3205FC-FC48-4A39-9FBD-B0035979DDFF', 'January 2010',
  '76D836AA-5D94-4374-BCBF-17F825177898', 'February 2010',
  '076DF31D-E151-4CC3-8E0A-7A21E35CF679', 'March 2010',
  'D4232D7D-0DB6-4E8B-AD19-456E8D286D67', 'April 2010',
  '18C7629E-5F96-4BA8-A2C8-31810A54F5B8', 'May 2010',
  '308738D5-18B0-4CB8-95FD-CDD9A5F49B62', 'June 2010',
  'A1A3C5AF-108A-45FD-ABEC-5B75DF31736D', 'July 2010',
  'E39537F7-D4B8-4042-930C-191A2EF18C73', 'August 2010',
  '0916C369-02A8-4C3D-9AD0-E72AF7C46025', 'September 2010',
  '32F1A453-65D6-41F0-A36F-D9837A868534', 'October 2010',
  '5800D663-13EA-457C-8CFD-632149D0AEDD', 'November 2010',
  '4E28B496-DD95-4300-82A6-53809E0F9CDA', 'December 2010',
  '258FD3CF-9C82-4112-B1B0-18EC1ECFED37', 'January 2011',
  'B3458687-D7E4-4068-8A57-3028D15A7408', 'February 2011',
  'AF70C509-22C8-4369-AEC6-81AEB02A59B7', 'March 2011',
  '0CB525D5-8593-436C-9EB0-68C6D549994D', 'April 2011',
  '852F70C7-9C9E-4093-9184-D89D5CE069F0', 'May 2011',
  'DDE7C7DD-E76A-4672-A166-159DA2110CE5', 'June 2011',
  '3C009D0B-2C32-4635-9B34-FFA7F4CB42E7', 'July 2011',
  'F14DDEA8-3541-40C6-AAC7-5A0024C928A8', 'August 2011',
  'E775644E-B0FF-44FA-9F8B-F731E231B507', 'September 2011',
  'C0177BCC-8925-431B-AC98-9AC87B8E9699', 'October 2011',
  'BEB9D90D-ED88-42D7-BD71-AE30E89BBDC9', 'November 2011',
  '79B9D6F6-2990-4C15-8914-7801AD90B4D7', 'December 2011',
  '634F47CA-D7D7-448E-A7BE-0371D029EB32', 'January 2012',
  '23B13CB9-1784-4DD3-9504-7E58427307A7', 'February 2012',
  '84C44DD1-20C8-4542-A1AF-C3BA2A191E25', 'March 2012',
  '3C1A9787-5E87-45E3-9B0B-21A6AB25BF4A', 'April 2012',
  'D0082A21-13E4-49F7-A31D-7F752F059DE9', 'May 2012',
  '4B83319E-E2A4-4CD0-9AAC-A0AB62CE3384', 'June 2012',
  '3E9B6E28-8A74-4432-AD2A-46133BDED728', 'July 2012',
  'C1156343-36C9-44FB-BED9-75151586227B', 'August 2012',
  '02A84536-D000-45FF-B71E-9203EFD2FE04', 'September 2012',
  '8C1ACB58-FEE7-4FF0-972C-A09A058667F8', 'October 2012',
  '7D0B34BB-97EB-40CE-8513-4B11EB4C1BD6', 'November 2012',
  'AD64315C-1421-4A96-89F4-464124776078', 'December 2012',
  'A769BB72-28FC-43C7-BA14-2E44725FED20', 'January 2013',
  'ED5E6E45-F92A-4096-BF7F-F84ECF59F0DB', 'February 2013',
  '147152D2-DFFC-4181-A837-11CB9211D091', 'March 2013',
  '7A6917B5-082B-48BA-9DFC-9B7034906FDC', 'April 2013',
  '3DAA6951-E853-47E4-B288-257DCDE1A45A', 'May 2013',
  '4A25C1F5-EA3D-4840-8E14-692DD6A57508', 'June 2013',
  '9326E352-E4F2-4BF7-AF54-3C06425F28A6', 'July 2013',
  'B6345F3A-AFA9-42FF-A5E7-DFC6C57B7EF8', 'August 2013',
  '462BE659-C07A-433A-874F-2362F01E07EA', 'September 2013',
  '21063288-61F8-4060-9629-9DBDD77E3242', 'October 2013',
  'BA6D0F21-C17B-418A-8ADD-B18289A02461', 'November 2013',
  'AFAFB7C5-798B-453D-891C-6765E4545CCC', 'December 2013',
  '7BC20D37-A4C7-4B84-BA08-8EC32EBF781C', 'January 2014',
  'FC5CF920-B37A-457B-9AB9-36ECC218A003', 'February 2014',
  '254C09FA-7763-4C39-8241-76517EF78744', 'March 2014',
  '54788934-6031-4F7A-ACED-5D055175AF71', 'April 2014',
  '91EFE48B-7F85-4A74-9F33-26952DA55C80', 'May 2014',
  '07C5D15E-5547-4A58-A94D-5642040F60A2', 'June 2014',
  '43E0374E-D98E-4266-AB02-AE415EC8E119', 'July 2014',
  '53B5DBC4-54C7-46E4-B056-C6F17947DBDC', 'August 2014',
  '98CB657B-9051-439D-9A5D-8D4EDF851D94', 'September 2014',
  '5612279E-542C-454D-87FE-92E7CBFDCF0F', 'October 2014',
  '7F08663E-6A54-4F86-A6B5-805ADDE50113', 'November 2014',
  '386A84B2-5559-41C1-AC7F-33E0D5DE0DF6', 'December 2014',
  '677022D4-7EC2-4F65-A906-10FD5BBCB34C', 'January 2015',
  '92D72885-37F5-42A2-B199-9DBBEF797448', 'February 2015',
  'CEF02A7E-71DD-4391-9BF6-BF5DEE8E9173', 'March 2015',
  '7AABE55A-B025-4688-99E9-8C66A2713025', 'April 2015',
  'F8F85141-8E6C-4FED-8D4A-8CF72D6FBA21', 'May 2015',
  '20DEE2FA-9862-4C40-A1D4-1E13F1B9E8A7', 'June 2015',
  '82835140-FC6B-4E05-A17F-A6B9C5D7F9C7', 'July 2015',
  '74E954EF-6B77-4758-8483-4E0F4D0A73C7', 'August 2015',
  'BC074C26-D04C-4625-A88C-862601491864', 'September 2015',
  '4C5E10AF-1307-4E66-A279-5877C605EEFB', 'October 2015',
  'FFF3C6DF-56FD-4A28-AA12-E45C3937AB41', 'November 2015',
  'EE51DBB1-AE48-4F16-B239-F4EB7B2B5EED', 'December 2015',
  'ED6134CC-62B9-4514-AC73-07401411E1BE', 'January 2016',
  'DD51B914-25C9-427C-BEC8-DA8BB2597585', 'February 2016',
  '3AC662F4-BBD5-4771-B2A0-164912094D5D', 'March 2016',
  '6F31010B-5919-41C2-94FB-E71E8EEE9C9A', 'April 2016',
  '156D44C7-D356-4303-B9D2-9B782FE4A304', 'May 2016',
  'E6F49BC4-1AEA-4648-B235-1F2A069449BF', 'June 2016',
  'E6F49BC4-1AEA-4648-B235-1F2A069449BF', 'July 2016',
  '0F13F87E-603E-4964-A9B4-BF923FB27B5D', 'August 2016',
  '2168C094-1DFC-43A9-B58E-EB323313845B', 'September 2016',
  '6AC744F7-F828-4CF8-A405-AA89845B2D98', 'October 2016',
  'E36D6367-DF23-4D09-B5B1-1FC38109F29C', 'November 2016',
  'F6945BD2-D48B-4B07-A7FB-A55C4F98A324', 'December 2016',
  'A5E600F5-A3CE-4C8E-8A14-D4133623CDC5', 'January 2017',
  'F83889D4-A24B-44AA-8E34-BCDD8912FAD7', 'March 2017',
  '507CBE5F-7915-416A-9E0E-B18FEA08237D', 'April 2017',
  'E43CFF1D-46DB-4239-A583-3828BB9EB66C', 'May 2017'
);

lastrun_version = version_table[version_guid];
if (isnull(lastrun_version))
  lastrun_version = 'unknown';
else
  set_kb_item(name:'SMB/MRT/Last_Run_Version', value:lastrun_version);

port = kb_smb_transport();

if (report_verbosity > 0)
{
  report =
    '\n  File                : ' + exe +
    '\n  Version             : ' + version +
    '\n  Release at last run : ' + lastrun_version +
    '\n  Report infection information to Microsoft : ';
  if (dont_report_to_ms == 1)
    report += 'No';
  else
    report += 'Yes';

  report += '\n';
  security_note(port:port, extra:report);
}
else security_note(port);
