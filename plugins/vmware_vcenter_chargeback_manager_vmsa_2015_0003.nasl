#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82899);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6549",
    "CVE-2014-6585",
    "CVE-2014-6587",
    "CVE-2014-6591",
    "CVE-2014-6593",
    "CVE-2014-6601",
    "CVE-2015-0383",
    "CVE-2015-0395",
    "CVE-2015-0400",
    "CVE-2015-0403",
    "CVE-2015-0406",
    "CVE-2015-0407",
    "CVE-2015-0408",
    "CVE-2015-0410",
    "CVE-2015-0412",
    "CVE-2015-0413",
    "CVE-2015-0421",
    "CVE-2015-0437"
  );
  script_bugtraq_id(
    70574,
    72132,
    72136,
    72137,
    72140,
    72142,
    72146,
    72148,
    72150,
    72154,
    72155,
    72159,
    72162,
    72165,
    72168,
    72169,
    72173,
    72175,
    72176
  );
  script_osvdb_id(
    113251,
    117224,
    117225,
    117226,
    117227,
    117228,
    117229,
    117230,
    117231,
    117232,
    117233,
    117234,
    117235,
    117236,
    117237,
    117238,
    117239,
    117240,
    117241
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"VMSA", value:"2015-0003");

  script_name(english:"VMware vCenter Chargeback Manager Multiple Java Vulnerabilities (VMSA-2015-0003) (POODLE)");
  script_summary(english:"Checks the version of java.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected
by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VMware vCenter Chargeback Manager installed on the
remote host is affected by a man-in-the-middle (MitM) information
disclosure vulnerability known as POODLE. The vulnerability is due to
the way SSL 3.0 handles padding bytes when decrypting messages
encrypted using block ciphers in cipher block chaining (CBC) mode.
MitM attackers can decrypt a selected byte of a cipher text in as few
as 256 tries if they are able to force a victim application to
repeatedly send the same data over newly created SSL 3.0 connections.
(CVE-2014-3566)

Additionally, unspecified vulnerabilities also exist in the following
bundled Java components :

  - 2D (CVE-2014-6585, CVE-2014-6591)

  - Deployment (CVE-2015-0403, CVE-2015-0406)

  - Hotspot (CVE-2014-6601, CVE-2015-0383, CVE-2015-0395,
    CVE-2015-0437)

  - Installation (CVE-2015-0421)

  - JAX-WS (CVE-2015-0412)

  - JSSE (CVE-2014-6593)

  - Libraries (CVE-2014-6549, CVE-2014-6587, CVE-2015-0400)

  - RMI (CVE-2015-0408)

  - Security (CVE-2015-0410)

  - Serviceability (CVE-2015-0413)

  - Swing (CVE-2015-0407)");
  script_set_attribute(attribute:"see_also", value:"https://www.vmware.com/security/advisories/VMSA-2015-0003");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Apr/5");
  # 2.7 http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2112011
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2fc26e85");
  # 2.6 http://kb.vmware.com/selfservice/microsites/search.do?language=en_US&cmd=displayKC&externalId=2113178
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?09fca0e3");

  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  # Java SE JDK and JRE 7 Update 75
  # http://www.oracle.com/technetwork/java/javase/7u75-relnotes-2389086.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e35b07");
  # Java SE JDK and JRE 6 Update 91
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Apply the vendor patch referenced in :

  - KB: 2112011 for vCenter Chargeback Manager 2.7
  - KB: 2113178 for vCenter Chargeback Manager 2.6");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_chargeback_manager");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_chargeback_manager_installed.nasl");
  script_require_keys("SMB/VMware vCenter Chargeback Manager/Version", "SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_name = 'VMware vCenter Chargeback Manager';
install  = get_single_install(app_name:app_name, exit_if_unknown_ver:TRUE);
version  = install['version'];
path     = install['path'];

if (version !~ '^2\\.[67]\\.')
  audit(AUDIT_NOT_INST, app_name + ' 2.6 / 2.7');

# Check version of java.exe
# 1.7.0_75 (7.0.750.x) for CBM 2.7
# 1.6.0_91 (6.0.910.x) for CBM 2.6
exe_path = hotfix_append_path(path:path, value:"jre\bin\java.exe");
exe_version = hotfix_get_fversion(path:exe_path);
hotfix_handle_error(error_code:exe_version['error'], file:exe_path, appname:app_name, exit_on_fail:TRUE);
hotfix_check_fversion_end();

exe_version = join(exe_version['value'], sep:'.');

if (version =~ "^2\.7\.")
  exe_fix_version = "7.0.750";
else
  exe_fix_version = "6.0.910";

if (ver_compare(ver:exe_version, fix:exe_fix_version, strict:FALSE) == -1)
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    report =
      '\n  Path              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Java EXE          : ' + exe_path +
      '\n  EXE version       : ' + exe_version +
      '\n  Fixed version     : ' + exe_fix_version +
      '\n';
    security_hole(extra:report, port:port);
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
