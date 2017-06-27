#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90189);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:42:40 $");

  script_cve_id(
    "CVE-2015-7675",
    "CVE-2015-7677",
    "CVE-2015-7680"
  );
  script_bugtraq_id(
    83191,
    83196,
    83198
  );
  script_osvdb_id(
    133770,
    133772,
    133775
  );
  script_xref(name:"IAVB", value:"2016-B-0035");

  script_name(english:"Ipswitch MOVEit DMZ < 8.2 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Ipswitch MOVEit DMZ.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Ipswitch MOVEit DMZ installed on the remote host is
prior to 8.2. It is, therefore, affected by multiple vulnerabilities :

  - A flaw exists in the Send as Attachment feature due to
    improper sanitization of user-supplied input to the
    'serverFileIds' parameter of mobile/sendMsg and the
    mobile/sendMsg' parameter of human.aspx. An
    authenticated, remote attacker can exploit this, via a
    a request with a valid FileID, to bypass authorization
    and read uploaded files. (CVE-2015-7675)

  - A flaw exists due to the MOVEitISAPI service returning
    different error messages depending on whether a FileID
    exists or not. An authenticated, remote attacker can
    exploit this, via the 'X-siLock-FileID' parameter in a
    download action, to enumerate valid FileIDs.
    (CVE-2015-7677)

  - A flaw exists in the machine.aspx script due to
    different error codes being returned depending on if a
    user account exists or not. An unauthenticated, remote
    attacker can exploit this, via a series of SOAP
    requests, to enumerate usernames. (CVE-2015-7680)");
# http://docs.ipswitch.com/MOVEit/DMZ82/ReleaseNotes/MOVEitReleaseNotes82.pdf
script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?16036f7d");
script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2016/Jan/95");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Ipswitch MOVEit DMZ version 8.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ipswitch:moveit_dmz");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","ipswitch_dmz_ftp_installed.nbin");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");
include("smb_func.inc");

appname = "Ipswitch MOVEit DMZ";
fix = "8.2";
port = kb_smb_transport();
install = get_single_install(app_name:appname, exit_if_unknown_ver:TRUE);
reportDetails = make_array();
reportOrder = make_list();
reportDetails["Installed Product Version"] = install['version'];
reportOrder = make_list(reportOrder, "Installed Product Version");
reportDetails["Installation Directory"] = install['path'];
reportOrder = make_list(reportOrder, "Installation Directory");
reportDetails["Installation Date"] = install['InstallDate'];
reportOrder = make_list(reportOrder, "Installation Date");
reportDetails["Fixed Version"] = fix;
reportOrder = make_list(reportOrder, "Fixed Version");
report = NULL;

if(ver_compare(ver:reportDetails["Installed Product Version"], fix:fix, strict:FALSE) < 0)
{
  if(!port) port = 445;
  report = 'The installed version of ' + appname + ' is affected by multiple vulnerabilities :\n' +
           report_items_str(report_items:reportDetails, ordered_fields:reportOrder);
  security_report_v4(
    port     : port,
    severity : SECURITY_WARNING,
    extra    : report
  );
}
else
{
  audit(AUDIT_INST_VER_NOT_VULN, appname, reportDetails["Installed Product Version"]);
}
