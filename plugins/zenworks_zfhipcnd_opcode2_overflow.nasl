#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(51833);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/15 19:41:09 $");

  script_cve_id("CVE-2011-0742");
  script_bugtraq_id(46024);
  script_osvdb_id(70694);

  script_name(english:"Novell ZENworks Handheld Management ZfHIPCND.exe Crafted TCP Request Remote Overflow");
  script_summary(english:"Checks the BuildDate of ZfHIPCND.exe"); 
 
  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host contains network service that is prone to a
buffer overflow attack."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"According to its build date, the version of the ZENworks Handheld
Management Access Point process (ZfHIPCND.exe) on the remote host is
affected by a buffer overflow vulnerability due to a failure to
accommodate variable-sized data during initialization of a buffer. 

By default, this process listens on TCP port 2400. An
unauthenticated, remote attacker that can connect to that port can
leverage this issue to execute arbitrary code in the context of the
affected application, which runs with SYSTEM privileges."
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.zerodayinitiative.com/advisories/ZDI-11-026/"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/fulldisclosure/2011/Jan/472"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.securityfocus.com/archive/1/archive/1/516045/100/0/threaded"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.novell.com/support/viewContent.do?externalId=7007663"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://download.novell.com/Download?buildid=x_x4cdA5yT8~"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Apply ZENworks 7 Handheld Management Support Pack 1 Interim Release 4
Hot Patch 6 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/01");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_handheld_management_zfhipcnd_buffer_overflow.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/ZENworks/ZfHIPCND/Installed");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


get_kb_item_or_exit('SMB/ZENworks/ZfHIPCND/Installed');

installed_builddate = get_kb_item_or_exit('SMB/ZENworks/ZfHIPCND/BuildDate', exit_code:1);

path = get_kb_item('SMB/ZENworks/ZfHIPCND/Path');
if (isnull(path)) path = 'n/a';

version = get_kb_item('SMB/ZENworks/ZfHIPCND/Version');
if (version) installed_version = version + ' ' + installed_builddate;
else installed_version = installed_builddate;


# Check the date.
pat = "Build ([0-9][0-9])/([0-9][0-9])/([0-9][0-9])";

match = eregmatch(pattern:pat, string:installed_builddate);
if (!match) exit(1, "Failed to parse the build date ("+installed_builddate+").");
installed_month = int(match[1]);
installed_day = int(match[2]);
installed_year = int(match[3]);

fixed_version = '7.1.4.10120 Build 01/20/11 15:31';
fixed_builddate = strstr(fixed_version, 'Build ');

match = eregmatch(pattern:pat, string:fixed_builddate);
if (!match) exit(1, "Failed to parse the build date ("+fixed_builddate+").");
fixed_month = int(match[1]);
fixed_day = int(match[2]);
fixed_year = int(match[3]);

if (
  installed_year < fixed_year ||
  (
    installed_year == fixed_year &&
    (
      installed_month < fixed_month ||
      (installed_month == fixed_month && installed_day < fixed_day)
    )
  )
)
{
  if (report_paranoia < 2)
  {
    status = get_kb_item_or_exit("SMB/svc/ZENworks for Handhelds IP Conduit");
    if (status != SERVICE_ACTIVE)
      exit(0, "The host is not affected since the Access Point service is not active even though its version is "+installed_version+".");
  }

  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0)
  {
    report = 
      '\n  File              : ' + path + "\ZfHIPCND.exe" +
      '\n  Installed version : ' + installed_version + 
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since the version of the Access Point process is "+installed_version+".");
