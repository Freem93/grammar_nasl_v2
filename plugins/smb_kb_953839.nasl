#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33881);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");

 script_cve_id("CVE-2007-5605", "CVE-2007-5606");
 script_bugtraq_id(27539, 29531, 29532, 30548);
 script_osvdb_id(40889, 46232, 46233);

 script_name(english:"MS KB953839: Cumulative Security Update of ActiveX Kill Bits");
 script_summary(english:"Determines if the newest kill bits are set");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update containing
ActiveX kill bits.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a list of kill bits for ActiveX controls
that are known to contain vulnerabilities. 

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues.");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released an advisory about this :

http://technet.microsoft.com/en-us/security/advisory/953839");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");


# Test each control.
info = "";
clsids = make_list(
  "{B60770C2-0390-41A8-A8DE-61889888D840}",
  "{44A6A9CA-AC5B-4C39-8FE6-17E7D06903A9}",
  "{76EE578D-314B-4755-8365-6E1722C001A2}",
  "{F89EF74A-956B-4BD3-A066-4F23DF891982}",
  "{101D2283-EED9-4BA2-8F3F-23DB860946EB}",
  "{69C462E1-CD41-49E3-9EC2-D305155718C1}",
  "{41473CFB-66B6-45B8-8FB3-2BC9C1FD87BA}",
  "{108092BF-B7DB-40D1-B7FB-F55922FCC9BE}",
  "{CF08D263-B832-42DB-8950-F40C9E672E27}",
  "{F1F51698-7B63-4394-8743-1F4CF1853DE1}",
  "{905BF7D7-6BC1-445A-BE53-9478AC096BEB}",
  "{916063A5-0098-4FB7-8717-1B2C62DD4E45}",
  "{AE2B937E-EA7D-4A8D-888C-B68D7F72A3C4}",
  "{AE6C4705-0F11-4ACB-BDD4-37F138BEF289}",
  "{FA8932FF-E064-4378-901C-69CB94E3A20A}",
  "{3604EC19-E009-4DCB-ABC5-BB95BF92FD8B}",
  "{65FB3073-CA8E-42A1-9A9A-2F826D05A843}",
  "{7EB2A2EC-1C3A-4946-9614-86D3A10EDBF3}",
  "{9BAFC7B3-F318-4BD4-BABB-6E403272615A}",
  "{05CDEE1D-D109-4992-B72B-6D4F5E2AB731}",
  "{977315A5-C0DB-4EFD-89C2-10AA86CA39A5}",
  "{1E0D3332-7441-44FF-A225-AF48E977D8B6}",
  "{B85537E9-2D9C-400A-BC92-B04F4D9FF17D}",
  "{2C2DE2E6-2AD1-4301-A6A7-DF364858EF01}",
  "{0270E604-387F-48ED-BB6D-AA51F51D6FC3}",
  "{FC28B75F-F9F6-4C92-AF91-14A3A51C49FB}",
  "{86C2B477-5382-4A09-8CA3-E63B1158A377}",
  "{8CC18E3F-4E2B-4D27-840E-CB2F99A3A003}",
  "{68BBCA71-E1F6-47B2-87D3-369E1349D990}",
  "{8DBC7A04-B478-41D5-BE05-5545D565B59C}",
  "{D986FE4B-AE67-43C8-9A89-EADDEA3EC6B6}",
  "{6CA73E8B-B584-4533-A405-3D6F9C012B56}",
  "{6E5E167B-1566-4316-B27F-0DDAB3484CF7}",
  "{A7866636-ED52-4722-82A9-6BAABEFDBF96}",
  "{B0A08D67-9464-4E73-A549-2CC208AC60D3}",
  "{3D6A1A85-DE54-4768-9951-053B3B02B9B0}",
  "{947F2947-2296-42FE-92E6-E2E03519B895}",
  "{47AF06DD-8E1B-4CA4-8F55-6B1E9FF36ACB}",
  "{B26E6120-DD35-4BEA-B1E3-E75F546EBF2A}",
  "{926618A9-4035-4CD6-8240-64C58EB37B07}",
  "{B95B52E9-B839-4412-96EB-4DABAB2E4E24}",
  "{CB05A177-1069-4A7A-AB0A-5E6E00DCDB76}",
  "{A233E654-53FF-43AA-B1E2-60DA2E89A1EC}",
  "{6981B978-70D9-40B9-B00E-903B6FC8CA8A}",
  "{C86EE68A-9C77-4441-BD35-14CC6CC4A189}",
  "{2875E7A5-EE3C-4FE7-A23E-DE0529D12028}",
  "{66E07EF9-4E89-4284-9632-6D6904B77732}",
  "{00D46195-B634-4C41-B53B-5093527FB791}",
  "{497EE41C-CE06-4DD4-8308-6C730713C646}",
  "{7A12547F-B772-4F2D-BE36-CE5D0FA886A1}",
  "{0B9C0C26-728C-4FDA-B8DD-59806E20E4D9}",
  "{F399F5B6-3C63-4674-B0FF-E94328B1947D}",
  "{8C7A23D9-2A9B-4AEA-BA91-3003A316B44D}",
  "{E6127E3B-8D17-4BEA-A039-8BB9D0D105A2}",
  "{A3796166-A03C-418A-AF3A-060115D4E478}",
  "{73BCFD0F-0DAA-4B21-B709-2A8D9D9C692A}",
  "{93C5524B-97AE-491E-8EB7-2A3AD964F926}",
  "{833E62AD-1655-499F-908E-62DCA1EB2EC6}",
  "{285CAE3C-F16A-4A84-9A80-FF23D6E56D68}",
  "{AA13BD85-7EC0-4CC8-9958-1BB2AA32FD0B}",
  "{4614C49A-0B7D-4E0D-A877-38CCCFE7D589}",
  "{974E1D88-BADF-4C80-8594-A59039C992EA}",
  "{692898BE-C7CC-4CB3-A45C-66508B7E2C33}",
  "{F6A7FF1B-9951-4CBE-B197-EA554D6DF40D}",
  "{038F6F55-C9F0-4601-8740-98EF1CA9DF9A}",
  "{652623DC-2BB4-4C1C-ADFB-57A218F1A5EE}",
  "{BA162249-F2C5-4851-8ADC-FC58CB424243}",
  "{9275A865-754B-4EDF-B828-FED0F8D344FC}",
  "{6C095616-6064-43ca-9180-CF1B6B6A0BE4}",
  "{E1A26BBF-26C0-401d-B82B-5C4CC67457E0}",
  "{A73BAEFA-EE65-494D-BEDB-DD3E5A34FA98}",
  "{5C6698D9-7BE4-4122-8EC5-291D84DBD4A0}",
  "{E4C97925-C194-4551-8831-EABBD0280885}",
  "{CC7DA087-B7F4-4829-B038-DA01DFB5D879}",
  "{14C1B87C-3342-445F-9B5E-365FF330A3AC}",
  "{60178279-6D62-43af-A336-77925651A4C6}",
  "{DC4F9DA0-DB05-4BB0-8FB2-03A80FE98772}",
  "{0C378864-D5C4-4D9C-854C-432E3BEC9CCB}",
  "{93441C07-E57E-4086-B912-F323D741A9D8}",
  "{CDAF9CEC-F3EC-4B22-ABA3-9726713560F8}",
  "{CF6866F9-B67C-4B24-9957-F91E91E788DC}",
  "{A95845D8-8463-4605-B5FB-4F8CFBAC5C47}",
  "{B9C13CD0-5A97-4C6B-8A50-7638020E2462}",
  "{C70D0641-DDE1-4FD7-A4D4-DA187B80741D}",
  "{DE233AFF-8BD5-457E-B7F0-702DBEA5A828}",
  "{AB049B11-607B-46C8-BBF7-F4D6AF301046}",
  "{910E7ADE-7F75-402D-A4A6-BB1A82362FCA}",
  "{42C68651-1700-4750-A81F-A1F5110E0F66}",
  "{BF931895-AF82-467A-8819-917C6EE2D1F3}",
  "{4774922A-8983-4ECC-94FD-7235F06F53A1}",
  "{E12DA4F2-BDFB-4EAD-B12F-2725251FA6B0}",
  "{C94188F6-0F9F-46B3-8B78-D71907BD8B77}",
  "{6470DE80-1635-4B5D-93A3-3701CE148A79}",
  "{17E67D4A-23A1-40D8-A049-EE34C0AF756A}",
  "{AB237044-8A3B-42BB-9EE1-9BFA6721D9ED}",
  "{784F2933-6BDD-4E5F-B1BA-A8D99B603649}"
);

foreach clsid (clsids)
{
  if (activex_get_killbit(clsid:clsid) == 0)
  {
    info += '  ' + clsid + '\n';
    if (!thorough_tests) break;
  }
}
activex_end();


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report = string(
      "\n",
      "The kill bit has not been set for the following control", s, " :\n",
      "\n",
      info
    );

    if (!thorough_tests)
    {
      report = string(
        report,
        "\n",
        "Note that Nessus did not check whether there were other kill bits\n",
        "that have not been set because the 'Perofrm thorough tests' setting\n",
        "was not enabled when this scan was run.\n"
      );
    }
    security_warning(port:kb_smb_transport(), extra:report);
  }
  else security_warning(kb_smb_transport());
}
