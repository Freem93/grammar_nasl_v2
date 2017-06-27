#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70172);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 22:04:46 $");

  script_cve_id("CVE-2013-2340", "CVE-2013-2341");
  script_bugtraq_id(60881, 60882);
  script_osvdb_id(94699, 94700);
  script_xref(name:"HP", value:"HPSBHF02888");
  script_xref(name:"IAVB", value:"2013-B-0108");
  script_xref(name:"HP", value:"SSRT100917");
  script_xref(name:"HP", value:"SSRT101120");
  script_xref(name:"HP", value:"emr_na-c03808969");

  script_name(english:"HP Multiple Network Products Unspecified Information Disclosure and Remote Code Execution (HPSBHF02888)");
  script_summary(english:"Checks model number to determine presence of flaw");

  script_set_attribute(attribute: "synopsis", value:"The remote host is missing a vendor-supplied software update.");
  script_set_attribute(attribute: "description", value:
"The remote HP router or switch could be missing a vendor-supplied
update that corrects an issue that a malicious attacker could remotely
exploit in order to cause a disclosure of information or execution of
code.");
  script_set_attribute(attribute: "solution", value:"Apply the vendor-specified update.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
  # https://h20566.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c03808969
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?201b73ae");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/h:hp:procurve_switch");

 script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/27");
 script_set_attribute(attribute:"patch_publication_date", value:"2013/06/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/27");

 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

 script_dependencies("ssh_get_info.nasl", "hp_procurve_version.nasl");
 script_require_keys("Host/HP_Switch", "Settings/ParanoidReport");
 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


if (!get_kb_item('Host/HP_Switch')) exit(0, "This is not an HP Switch.");

rev = get_kb_item("Host/HP_Switch/SoftwareRevision");

model = get_kb_item_or_exit("Host/HP_Switch/Model");
if ( model == "unknown" ) exit(0, "The model number could not be obtained.");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

flag = 0;
fix_version = "";

# check the affected models
temp_fix_version="12500_5.20.R1825P01";
products = make_list(
  "JC085A",
  "JC086A",
  "JC652A",
  "JC653A",
  "JC654A",
  "JC655A",
  "JF430A",
  "JF430B",
  "JF430C",
  "JF431A",
  "JF431B",
  "JF431C",
  "S12508",
  "S12518");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="10500_5.20.R1208-US";
products = make_list(
  "JC611A",
  "JC612A",
  "JC613A",
  "JC748A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S9500E_5.20.R1825P01";
products = make_list(
  "JC124A",
  "JC124B",
  "JC125A",
  "JC125B",
  "JC474A",
  "JC474B",
  "S9512E",
  "S9508E-V",
  "S9505E");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="7500_5.20.R6708-US";
products = make_list(
  "JD238A",
  "JD238B",
  "JD239A",
  "JD239B",
  "JD240A",
  "JD240B",
  "JD241A",
  "JD241B",
  "JD242A",
  "JD242B",
  "JD243A",
  "JD243B",
  "JE164A",
  "JE165A",
  "JE166A",
  "JE167A",
  "JE168A",
  "JE169A",
  "S7502E",
  "S7503E",
  "S7503E-S",
  "S7506E",
  "S7506E-V",
  "S7510E");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="6125-CMW520-R2105";
products = make_list(
  "658250-B21",
  "658247-B21");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5830_5.20.R1118-US";
products = make_list(
  "JC691A",
  "JC694A",
  "JG316A",
  "JG374A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5800-5820X_5.20.R1807P02-US";
products = make_list(
  "JC099A",
  "JC100A",
  "JC101A",
  "JC102A",
  "JC103A",
  "JC104A",
  "JC105A",
  "JC106A",
  "JG219A",
  "JG225A",
  "JG242A",
  "JG243A",
  "JG254A",
  "JG255A",
  "JG256A",
  "JG257A",
  "JG258A",
  "JG259A",
  "S5800-32C",
  "S5800-32C-PWR",
  "S5800-32F",
  "S5800-56C",
  "S5800-56C-PWR",
  "S5800-60C-PWR",
  "S5820X-28C",
  "S5820X-28S");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S5600_3.10.R1702P42";
products = make_list(
  "JD391A",
  "JD392A",
  "JD393A",
  "JD394A",
  "JD395A",
  "S5600-26C",
  "S5600-26C-PWR",
  "S5600-26F",
  "S5600-50C",
  "S5600-50C-PWR");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5500.EI-4800G_R2220-US";
products = make_list(
  "JD373A",
  "JD374A",
  "JD375A",
  "JD376A",
  "JD377A",
  "JD378A",
  "JD379A",
  "JG240A",
  "JG241A",
  "JG249A",
  "JG250A",
  "JG251A",
  "JG252A",
  "JG253A",
  "S5500-28C-EI",
  "S5500-28F-EI",
  "S5500-52C-EI",
  "S5500-28C-EI-DC",
  "S5500-28C-PWR-EI",
  "S5500-28F-EI",
  "S5500-52C-PWR-EI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5500.SI_R2220";
products = make_list(
  "JD369A",
  "JD370A",
  "JD371A",
  "JD372A",
  "JG238A",
  "JG239A",
  "S5500-28C-SI",
  "S5500-52C-SI",
  "S5500-28C-PWR-SI",
  "S5500-52C-PWR-SI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5500.HI_5.20.R5105-US";
products = make_list(
  "JG311A",
  "JG312A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="E5500G_03.03.02p21";
products = make_list(
  "JE088A",
  "JE089A",
  "JE090A",
  "JE091A",
  "JE092A",
  "JE093A",
  "JE094A",
  "JE095A",
  "JE096A",
  "JE097A",
  "JF551A",
  "JF552A",
  "JF553A",
  "5500G-EI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="E5500_03.03.02p21";
products = make_list(
  "JE099A",
  "JE100A",
  "JE101A",
  "JE102A",
  "JE103A",
  "JE104A",
  "JE105A",
  "JE106A",
  "JE107A",
  "JE108A",
  "JE109A",
  "JE110A",
  "5500-SI",
  "5500-EI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5120.SI_5.20.R1513P07";
products = make_list(
  "JE072A",
  "JE073A",
  "JE074A",
  "JG091A",
  "JG092A",
  "S5120-28P-HPWR-SI",
  "S5120-28P-PWR-SI",
  "S5120-20P-SI",
  "S5120-28P-SI",
  "S5120-52P-SI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5120.EI-4210G-4510G_R2220-US";
products = make_list(
  "JE066A",
  "JE067A",
  "JE068A",
  "JE069A",
  "JE070A",
  "JE071A",
  "JG236A",
  "JG237A",
  "JG245A",
  "JG246A",
  "JG247A",
  "JG248A",
  "S5120-24P-EI",
  "S5120-28C-EI",
  "S5120-48P-EI",
  "S5120-52C-EI",
  "S5120-28C-PWR-EI",
  "S5120-52C-PWR-EI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S5100.SI_3.10.R2221P07";
products = make_list(
  "JD348A",
  "JD349A",
  "JD356A",
  "JD357A",
  "S5100-16P-SI",
  "S5100-24P-SI",
  "S5100-48P-SI",
  "S5100-8P-SI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S5100.EI_3.10.R2221P07";
products = make_list(
  "JD344A",
  "JD345A",
  "JD346A",
  "JD347A",
  "JD350A",
  "JD351A",
  "JD352A",
  "JD353A",
  "JD354A",
  "JD355A",
  "S5100-16P-EI",
  "S5100-16P-PWR-EI",
  "S5100-24P-EI",
  "S5100-26C-EI",
  "S5100-26C-PWR-EI",
  "S5100-48P-EI",
  "S5100-50C-EI",
  "S5100-50C-PWR-EI",
  "S5100-8P-EI",
  "S5100-8P-PWR-EI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5500.EI-4800G_R2220-US";
products = make_list(
  "JD007A",
  "JD008A",
  "JD009A",
  "JD010A",
  "JD011A",
  "4800G");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5120.EI-4210G-4510G_R2220-US";
products = make_list(
  "JE045A",
  "JE046A",
  "JE047A",
  "JE048A",
  "4500");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="s4o03_01_15s168";
products = make_list(
  "JE021A",
  "JE023A",
  "JE024A",
  "JE026A",
  "JE027A",
  "JE028A",
  "JE030A",
  "JE031A",
  "JE032A",
  "4210");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S4210A_3.10.R2215P12";
products = make_list(
  "JE022A",
  "JE025A",
  "JE029A",
  "JE033A",
  "JF427A",
  "4210");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="5120.EI-4210G-4510G_R2220-US";
products = make_list(
  "JF844A",
  "JF845A",
  "JF846A",
  "4210-24G",
  "4210-48G",
  "E4210-24G-PoE");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="s3t03_02_07s168";
products = make_list(
  "JE015A",
  "JE016A",
  "JE017A",
  "JE018A",
  "JE019A",
  "JE020A",
  "4200G",
  "4200G-NTG");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S3610-5510_5.20.R5319P04";
products = make_list(
  "JD335A",
  "JD336A",
  "JD337A",
  "JD338A",
  "S3610-28F",
  "S3610-28P",
  "S3610-28TP",
  "S3610-52P");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="3600V2_5.20.R2108";
products = make_list(
  "JG299A",
  "JG300A",
  "JG301A",
  "JG302A",
  "JG303A",
  "JG304A",
  "JG305A",
  "JG306A",
  "JG307A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S3600.SI_3.10.R1702P42";
products = make_list(
  "JD325A",
  "JD327A",
  "JD329A",
  "JD330A",
  "JD332A",
  "S3600-28P-PWR-SI",
  "S3600-28P-SI",
  "S3600-28TP-SI",
  "S3600-52P-PWR-SI",
  "S3600-52P-SI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S3600.EI_3.10.R1702P42";
products = make_list(
  "JD326A",
  "JD328A",
  "JD331A",
  "JD333A",
  "JD334A",
  "S3600-28F-EI",
  "S3600-28P-EI",
  "S3600-28P-PWR-EI",
  "S3600-52P-EI",
  "S3600-52P-PWR-EI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="3100V2_5.20.R5203P01";
products = make_list(
  "JD313B",
  "JD318B",
  "JD319B",
  "JD320B",
  "JG221A",
  "JG222A",
  "JG223A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="3100V2.48_5.20.R2108";
products = make_list(
  "JG315A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S3100.SI_3.10.R2215P12";
products = make_list(
  "JD302A",
  "JD303A",
  "JD304A",
  "JD305A",
  "JD306A",
  "JD307A",
  "JD308A",
  "JD309A",
  "JD310A",
  "S3100-16C-SI",
  "S3100-16T-SI",
  "S3100-26C-SI",
  "S3100-26T-SI",
  "S3100-8C-SI",
  "S3100-8T-SI");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="S3152_3.10.R1702P42";
products = make_list(
  "JD317A",
  "S3100-52P");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="1910_5.20.R1513P07";
products = make_list(
  "JE005A",
  "JE006A",
  "JE007A",
  "JE008A",
  "JE009A",
  "JG348A",
  "JG349A",
  "JG350A",
  "2900",
  "2900G");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="8800_5.20.R3352";
products = make_list(
  "JC147A",
  "JC147B",
  "JC148A",
  "JC148B",
  "JC149A",
  "JC149B",
  "JC150A",
  "JC150B",
  "SR8805",
  "SR8808",
  "SR8812",
  "SR8802");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="R5000_3.14p13";
products = make_list(
  "JD935A",
  "JD943A",
  "JD944A",
  "JD945A",
  "JD946A",
  "5642",
  "5009",
  "5012",
  "5231",
  "5232",
  "5640",
  "5680",
  "5682");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="R301X_1.40.22";
products = make_list(
  "JD916A",
  "JD917A",
  "JD918A",
  "JD919A",
  "JG005A",
  "3012",
  "3013",
  "3016",
  "3018");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="R6000_3.14p13";
products = make_list(
  "JD967A",
  "JD972A",
  "6040",
  "6080");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR20.SI_5.20.R2312P20";
products = make_list(
  "JD432A",
  "JD662A",
  "JD663A",
  "JD663B",
  "JD664A",
  "JF228A",
  "JF283A",
  "RT-MSR2020-AC-OVS-H3C",
  "RT-MSR2040-AC-OVS-H3",
  "MSR 20-20",
  "MSR 20-21",
  "MSR 20-40",
  "MSR-20-21");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR201X_5.20.R2312P20";
products = make_list(
  "JD431A",
  "JD667A",
  "JD668A",
  "JD669A",
  "JD670A",
  "JD671A",
  "JD672A",
  "JD673A",
  "JD674A",
  "JD675A",
  "JD676A",
  "JF236A",
  "JF237A",
  "JF238A",
  "JF239A",
  "JF240A",
  "JF241A",
  "JF806A",
  "JF807A",
  "JF808A",
  "JF809A",
  "JF817A",
  "JG209A",
  "JG210A",
  "MSR 20-15",
  "MSR 20-10",
  "RT-MSR2011-AC-OVS-H3",
  "RT-MSR2012-AC-OVS-H3",
  "RT-MSR2012-AC-OVS-W-H3",
  "RT-MSR2012-T-AC-OVS-H3",
  "RT-MSR2013-AC-OVS-H3",
  "RT-MSR2013-AC-OVS-W-H3",
  "RT-MSR2015-AC-OVS-A-H3",
  "RT-MSR2015-AC-OVS-AW-H3",
  "RT-MSR2015-AC-OVS-I-H3",
  "RT-MSR2015-AC-OVS-IW-H3",
  "MSR 20-11",
  "MSR 20-12",
  "MSR 20-12 T1",
  "MSR 20-13",
  "MSR 20-13 W",
  "MSR 20-15 A",
  "MSR 20-15 A W",
  "MSR 20-15 I",
  "MSR 20-15 IW",
  "MSR20-12 W");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR30.SI_5.20.R2312P20";
products = make_list(
  "JD654A",
  "JD657A",
  "JD658A",
  "JD660A",
  "JD661A",
  "JD666A",
  "JF229A",
  "JF230A",
  "JF232A",
  "JF235A",
  "JF284A",
  "JF287A",
  "JF801A",
  "JF802A",
  "JF803A",
  "JF804A",
  "MSR 30-20",
  "MSR 30-40",
  "RT-MSR3020-AC-POE-OVS-H3",
  "RT-MSR3020-DC-OVS-H3",
  "RT-MSR3040-AC-OVS-H",
  "RT-MSR3040-AC-POE-OVS-H3",
  "RT-MSR3060-AC-OVS-H3",
  "RT-MSR3060-AC-POE-OVS-H3",
  "RT-MSR3060-DC-OVS-H3",
  "MSR 30-20",
  "MSR 30-20 POE",
  "MSR 30-40",
  "MSR 30-40 POE",
  "MSR 30-60",
  "MSR 30-60 POE",
  "RT-MSR3040-AC-OVS-AS-H3");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR3016.SI_5.20.R2312P20";
products = make_list(
  "JD659A",
  "JD665A",
  "JF233A",
  "JF234A",
  "RT-MSR3016-AC-OVS-H3",
  "RT-MSR3016-AC-POE-OVS-H3",
  "MSR 30-16",
  "MSR 30-16 POE");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR301X.SI_5.20.R2312P20";
products = make_list(
  "JF800A",
  "JF816A",
  "JG182A",
  "JG183A",
  "JG184A",
  "MSR 30-10",
  "RT-MSR3011-AC-OVS-H3");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR50.SI_5.20.R2312P20";
products = make_list(
  "JD433A",
  "JD653A",
  "JD655A",
  "JD656A",
  "JF231A",
  "JF285A",
  "JF640A",
  "MSR 50-40",
  "MSR5040-DC-OVS-H3C",
  "RT-MSR5060-AC-OVS-H3",
  "MSR 50-60");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR50.EPUSI_5.20.R2312P20";
products = make_list(
  "JD429A",
  "JD429B",
  "MSR 50");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR9XX_5.20.R2312P20";
products = make_list(
  "JF812A",
  "JF813A",
  "JF814A",
  "JF815A",
  "JG207A",
  "JG208A",
  "MSR 900",
  "MSR 920");

temp_fix_version="MSR20.SI_5.20.R2315L02.RU";
products = make_list(
  "JD663B",
  "JF228A",
  "JF283A",
  "RT-MSR2020-AC-OVS-H3C",
  "RT-MSR2040-AC-OVS-H3");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR201X_5.20.R2315L02.RU";
products = make_list(
  "JD431A",
  "JF236A",
  "JF237A",
  "JF238A",
  "JF239A",
  "JF240A",
  "JF241A",
  "JF806A",
  "JF807A",
  "JF808A",
  "JF809A",
  "JF817A",
  "MSR 20-10",
  "RT-MSR2015-AC-OVS-I-H3",
  "RT-MSR2015-AC-OVS-A-H3",
  "RT-MSR2015-AC-OVS-AW-H3",
  "RT-MSR2011-AC-OVS-H3",
  "RT-MSR2013-AC-OVS-H3",
  "RT-MSR2012-AC-OVS-H3",
  "RT-MSR2012-T-AC-OVS-H3",
  "RT-MSR2012-AC-OVS-W-H3",
  "RT-MSR2013-AC-OVS-W-H3",
  "RT-MSR2015-AC-OVS-IW-H3",
  "MSR 20-15");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR30.SI_5.20.R2315L02.RU";
products = make_list(
  "JF229A",
  "JF230A",
  "JF235A",
  "JF284A",
  "JF287A",
  "JF801A",
  "JF802A",
  "JF803A",
  "JF804A",
  "RT-MSR3040-AC-OVS-H",
  "RT-MSR3060-AC-OVS-H3",
  "RT-MSR3020-DC-OVS-H3",
  "MSR 30-20",
  "MSR 30-40",
  "RT-MSR3060-DC-OVS-H3",
  "RT-MSR3020-AC-POE-OVS-H3",
  "RT-MSR3040-AC-POE-OVS-H3",
  "RT-MSR3060-AC-POE-OVS-H3");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR301X.SI_5.20.R2315L02.RU";
products = make_list(
  "JF800A",
  "JF816A",
  "JG182A",
  "JG183A",
  "JG184A",
  "RT-MSR3011-AC-OVS-H3",
  "MSR 30-10");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR3016.SI_5.20.R2315L02.RU";
products = make_list(
  "JF233A",
  "JF234A",
  "RT-MSR3016-AC-OVS-H3",
  "RT-MSR3016-AC-POE-OVS-H3");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR50.SI_5.20.R2315L02.RU";
products = make_list(
  "JD433A",
  "JD653A",
  "JD655A",
  "JD656A",
  "JF231A",
  "JF285A",
  "JF640A",
  "MSR 50-40",
  "MSR 50",
  "MSR 50-60",
  "RT-MSR5060-AC-OVS-H3",
  "MSR5040-DC-OVS-H3C");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR50.EPUSI_5.20.R2315L02.RU";
products = make_list(
  "JD429B",
  "MSR 50");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="MSR9XX.SI_5.20.R2315L02.RU";
products = make_list(
  "JF812A",
  "JF813A",
  "JF814A",
  "JF815A",
  "MSR 900",
  "MSR 920");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="AF1000S.EI_AF1000A.EI_3.40.R3721P06";
products = make_list(
  "JD270A",
  "JD271A",
  "JG213A",
  "JG214A");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="R304X_2.41.p09";
products = make_list(
  "JD922A",
  "JD923A",
  "3040 ");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

temp_fix_version="R3036_2.41.p09";
products = make_list(
  "JD921A",
  "3036");
foreach temp (products)
{
  if (temp == model && temp_fix_version != rev)
  {
    flag++;
    if (fix_version) fix_version += ", ";
    fix_version += temp_fix_version;
  }
}

# report as needed
if (flag)
{
  report = string(
    "The Remote HP system is not patched :\n",
    "  Model #: ", model, "\n",
    "\n",
    "    Current Software Revision : ", rev, "\n",
    "    Suggested Software Version : ", fix_version, "\n"
  );

  security_hole(port:0, extra:report);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
