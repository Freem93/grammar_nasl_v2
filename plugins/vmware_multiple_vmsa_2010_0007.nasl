#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45541);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/29 20:13:36 $");

  script_cve_id(
    "CVE-2009-1564",
    "CVE-2009-1565",
    "CVE-2009-2042",
    "CVE-2009-3707",
    "CVE-2009-3732",
    "CVE-2010-1138",
    "CVE-2010-1140",
    "CVE-2010-1141",
    "CVE-2010-1142"
  );
  script_bugtraq_id(39345, 39363, 39364, 39392, 39394, 39395, 39396, 39397);
  script_osvdb_id(
    54915,
    58728,
    63605,
    63607,
    63614,
    63615,
    63858,
    63859,
    63860
  );
  script_xref(name:"VMSA", value:"2010-0007");
  script_xref(name:"IAVA", value:"2010-A-0066");
  script_xref(name:"Secunia", value:"36712");
  script_xref(name:"Secunia", value:"39206");

  script_name(english:"VMware Products Multiple Vulnerabilities (VMSA-2010-0007)");
  script_summary(english:"Checks vulnerable versions of VMware products");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization application affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"A VMware product (Player, Workstation, or Movie Decoder) detected on
the remote host has one or more of the following vulnerabilities :

  - The VMnc media codec has multiple heap overflow
    vulnerabilities.  A remote attacker could exploit these
    issues by tricking a user into requesting a malicious
    web page or opening a malicious file.
    (CVE-2009-1564, CVE-2009-1565)

  - A flaw in the 3rd party libpng library could allow an
    attacker to read sensitive portions of memory.
    (CVE-2009-2042)

  - A flaw in vmware-authd could lead to a denial of service
    service on Windows-based hosts. (CVE-2009-3707)

  - A format string vulnerability exists in the VMware
    Remote
    Console Plug-in.  A remote attacker could exploit this
    by tricking a user into requesting a malicious web
    page, resulting in arbitrary code execution.
    (CVE-2009-3732)

  - A flaw in the virtual networking stack could result in
    an information leak, causing memory from a guest VM to
    be sent to host's physical network. (CVE-2010-1138)

  - A vulnerability in the USB service allows a local
    attacker to elevate privileges by placing a malicious
    file in a certain location.  This vulnerability only
    affects Workstation and Player installed on Windows.
    (CVE-2010-1140)

  - A flaw in the way VMware libraries are referenced could
    allow a remote attacker to execute arbitrary code in a
    guest Windows VM by tricking a user into requesting a
    malicious file. (CVE-2010-1141)

  - A flaw in the way VMware executables are loaded could
    allow a malicious user to execute arbitrary code in a
    guest Windows VM by planting a malicious file in a
    a certain location. (CVE-2010-1142)");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-36/");
  script_set_attribute(attribute:"see_also", value:"http://secunia.com/secunia_research/2009-37/");
   # http://www.verisigninc.com/en_US/products-and-services/network-intelligence-availability/idefense/public-vulnerability-reports/articles/index.xhtml?id=866
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8db51821");
  script_set_attribute(attribute:"see_also", value:"http://www.acrossecurity.com/aspr/ASPR-2010-04-12-1-PUB.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.acrossecurity.com/aspr/ASPR-2010-04-12-2-PUB.txt");
  script_set_attribute(attribute:"see_also", value:"http://dsecrg.com/pages/vul/show.php?id=153");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Apr/76");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2010-0007.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to :

  - VMware Workstation 6.5.4 / 7.0.1 or later.
    - VMware Player 2.5.4 / 3.0.1 or later.
    - VMware Movie Decoder (standalone) 6.5.4 or later.
    - VMware Remote Console Plug-in latest version
    (refer to the advisory for instructions)

In addition to patching, VMware Tools must be updated on all guest VMs
in order to completely mitigate certain vulnerabilities. Refer to the
VMware advisory for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(134, 200);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vmware_player");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:vmware:vmware_workstation");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "vmware_workstation_detect.nasl", "vmware_player_detect.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("audit.inc");

port = kb_smb_transport();
report = "";
vuln = NULL;

commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

# Check if VMware Remote Console Plug-in / Movie Decoder are installed
list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");

vmrc_installed = FALSE;
decoder_installed = FALSE;
foreach name (list)
{
  if (name == 'VMware Remote Console Plug-in')
    vmrc_installed = TRUE;

  if (name == 'VMware Movie Decoder')
    decoder_installed = TRUE;
}

# Check for VMware Workstation
version = get_kb_item("VMware/Workstation/Version");
if (version)
{
 v = split(version, sep:".", keep:FALSE);

 if (( int(v[0]) < 6 ) ||
     ( int(v[0]) == 6 && int(v[1]) < 5) ||
     ( int(v[0]) == 6 && int(v[1]) == 5 && int(v[2]) < 4)
   )
 {
   vuln = TRUE;

   report =
     '\n  Product           : VMware Workstation'+
     '\n  Installed version : '+version+
     '\n  Fixed version     : 6.5.4\n';
 }
 else if (int(v[0]) == 7 && int(v[1]) == 0 && int(v[2]) < 1)
 {
   vuln = TRUE;

   report =
     '\n  Product           : VMware Workstation'+
     '\n  Installed version : '+version+
     '\n  Fixed version     : 7.0.1\n';
 }
 else if (isnull(vuln)) vuln = FALSE;
}
else if (decoder_installed)
{
  # If Workstation is not installed, check if the standalone Movie Decoder is
  # present and vulnerable
  if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

  if (hotfix_is_vulnerable(file:"vmnc.dll", version:"6.5.4", dir:"\system32"))
  {
    vuln = TRUE;
    hf_report = split(hotfix_get_report(), sep:'\n', keep:FALSE);
    report = '\n  Product : VMware Movie Decoder'+
             '\n  ' + hf_report[1]+
             '\n  ' + hf_report[2]+'\n';
  }

  hotfix_check_fversion_end();
}

# Check for VMware Player
version = get_kb_item("VMware/Player/Version");
if (version)
{
  v = split(version, sep:".", keep:FALSE);
  if (( int(v[0]) < 2 ) ||
      ( int(v[0]) == 2 && int(v[1]) < 5) ||
      ( int(v[0]) == 2 && int(v[1]) == 5 && int(v[2]) < 4)
    )
  {
    vuln = TRUE;
    report +=
      '\n  Product           : VMware Player'+
      '\n  Installed version : '+version+
      '\n  Fixed version     : 2.5.4\n';
  }
  else if (int(v[0]) == 3 && int(v[1]) == 0 && int(v[2]) < 1)
  {
    vuln = TRUE;
    report +=
      '\n  Product           : VMware Player'+
      '\n  Installed version : '+version+
      '\n  Fixed version     : 3.0.1\n';
  }
  else if (isnull(vuln)) vuln = FALSE;
}

# Check VMware Remote Console Plug-in
if (vmrc_installed)
{
  name    =  kb_smb_name();
  port    =  kb_smb_transport();
  login   =  kb_smb_login();
  pass    =  kb_smb_password();
  domain  =  kb_smb_domain();

  # Didn't find install location in the registry anywhere, but it appears to
  # always be installed in the common files dir
  path = commonfiles+"\VMware\VMware Remote Console Plug-in";
  share = ereg_replace(pattern:'^([A-Za-z]):.*', replace:"\1$", string:path);
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\vmware-vmrc.exe", string:path);

  if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
  rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
  if (rc != 1)
  {
   NetUseDel();
   exit(1, "Can't connect to "+share+" share.");
  }

  fh = CreateFile(
    file:exe,
    desired_access:GENERIC_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  # Grab the version number if the file was opened successfully.  Otherwise,
  # display a debug message but don't bail out
  if (fh)
  {
    ver = GetProductVersion(handle:fh);
    CloseFile(handle:fh);
    NetUseDel();
  }
  else
  {
    NetUseDel();
    exit(1, "Error opening '"+path+"'.");
  }

  # According to the advisory this is the only version that's affected,
  # but it doesn't mention what the latest/fixed version is
  if (ver && ver == 'e.x.p build-158248')
  {
    report +=
      '\n  Product           : VMware Remote Console Plug-in'+
      '\n  Installed version : '+ver+'\n';
  }
  else if (isnull(vuln)) vuln = FALSE;
}

if (isnull(vuln)) exit(0, "No VMware products were detected on this host.");
if (!vuln) exit(0, "The host is not affected.");

if (report_verbosity > 0)
  security_hole(port:port, extra:report);
else
  security_hole();
