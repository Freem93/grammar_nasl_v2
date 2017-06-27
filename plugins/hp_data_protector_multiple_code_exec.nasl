#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53857);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/08/22 20:52:04 $");

  script_cve_id(
    "CVE-2011-1728", 
    "CVE-2011-1729", 
    "CVE-2011-1730", 
    "CVE-2011-1731", 
    "CVE-2011-1732", 
    "CVE-2011-1733", 
    "CVE-2011-1734", 
    "CVE-2011-1735", 
    "CVE-2011-1736",
    "CVE-2011-2399"
  );
  script_bugtraq_id(47638, 48917);
  script_osvdb_id(
    72187,
    72188,
    72189,
    72190,
    72191,
    72192,
    72193,
    72194,
    72195,
    74249
  );
  script_xref(name:"ZDI", value:"ZDI-11-144");
  script_xref(name:"ZDI", value:"ZDI-11-145");
  script_xref(name:"ZDI", value:"ZDI-11-146");
  script_xref(name:"ZDI", value:"ZDI-11-147");
  script_xref(name:"ZDI", value:"ZDI-11-148");
  script_xref(name:"ZDI", value:"ZDI-11-149");
  script_xref(name:"ZDI", value:"ZDI-11-150");
  script_xref(name:"ZDI", value:"ZDI-11-151");
  script_xref(name:"ZDI", value:"ZDI-11-152");
  script_xref(name:"HP", value:"emr_na-c02810240");
  script_xref(name:"HP", value:"HPSBMA02668");
  script_xref(name:"HP", value:"SSRT100474");
  script_xref(name:"HP", value:"emr_na-c02940981");
  script_xref(name:"HP", value:"HPSBMU02669");
  script_xref(name:"HP", value:"SSRT100346");

  script_name(english:"HP Data Protector < A.06.20 Multiple Vulnerabilities");
  script_summary(english:"Does a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The backup service running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version and build number, the HP Data Protector
application running on the remote host is affected by the following
vulnerabilities :

  - Multiple buffer overflow conditions exist in the Backup
    Client Service (OmniInet.exe) that allow an
    unauthenticated, remote attacker to execute arbitrary
    code on the affected host as a privileged user. Note
    that these issues only affect HP Data Protector
    installations running on Windows. (CVE-2011-1728,
    CVE-2011-1729, CVE-2011-1730, CVE-2011-1731,
    CVE-2011-1732, CVE-2011-1733, CVE-2011-1734,
    CVE-2011-1735)

  - A directory traversal vulnerability exists in the Backup
    Client Service (OmniInet.exe) that allows an
    unauthenticated, remote attacker to view the contents of
    arbitrary files on the affected host. Note that this
    issue only affects HP Data Protector installations
    running on Windows. (CVE-2011-1736)

  - A flaw exists in the Media Management Daemon (mmd) that
    allows an unauthenticated, remote attacker to cause a
    denial of service condition. (CVE-2011-2399)");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-144/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-145/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-146/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-147/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-148/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-149/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-150/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-151/");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-152/");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/282");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/285");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/286");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/287");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/288");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/289");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/290");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/291");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/292");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2011/Apr/293");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c02810240
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?56b6a2b8");
  # http://h20564.www2.hpe.com/hpsc/doc/public/display?docId=emr_na-c02940981
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?97080bc0");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant patches referenced in the HP advisories.
Alternatively, enable the encrypted control communication services.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/10");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:storage_data_protector");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:data_protector");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("hp_data_protector_installed.nasl","hp_data_protector_installed_local.nasl");
  script_require_keys("Services/data_protector/version");
  script_require_ports("Services/hp_openview_dataprotector", 5555);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

port = get_service(svc:'hp_openview_dataprotector', default:5555, exit_on_fail:TRUE);

# Version numbers from HP's site:
version = get_kb_item_or_exit("Services/data_protector/version");

if (version == "A.06.11" || version == "A.06.10" || version == "A.06.00")
{
  report = '\n  Installed version : ' + version + 
           '\n  Fixed version     : A.06.20\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);

}
else if (version == "unknown") audit(AUDIT_UNKNOWN_APP_VER, "HP Data Protector");
else audit(AUDIT_INST_VER_NOT_VULN,"HP Data Protector", version);
