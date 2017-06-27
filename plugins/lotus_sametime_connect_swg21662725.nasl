#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72619);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/03/04 15:09:31 $");

  script_cve_id("CVE-2013-6727");
  script_bugtraq_id(65266);
  script_osvdb_id(102658);

  script_name(english:"IBM Lotus Sametime Connect Client Information Disclosure");
  script_summary(english:"Checks version of IBM Lotus Sametime Connect Client");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host has a chat client that is affected by an
information disclosure vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of IBM Lotus Sametime Connect installed on the remote
Windows host is potentially affected by an information disclosure
vulnerability.  A flaw in the application allows installation and
execution of unsigned Java plugins, which may access confidential user
information."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_security_bulletin_unsigned_java_plugins_cve_2013_6727?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?54d8c912");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=swg21662725");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/21");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:sametime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("lotus_sametime_connect_installed.nasl");
  script_require_keys("SMB/IBM Lotus Sametime Client/Path", "SMB/IBM Lotus Sametime Client/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

app_name = "IBM Lotus Sametime Connect Client";
version = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Version');
path    = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Path');
fixpackdate = get_kb_item('SMB/IBM Lotus Sametime Client/fixpackdate');

vuln = FALSE;
fixdate = NULL;

# Only 8.5.2 and 9.0.0 are affected.
if (version =~ "^8\.5\.2( .*)?$")
{
  # Check the fixpack timestamp
  if (isnull(fixpackdate)) vuln = TRUE;
  else
  {
    fixdate = "20131203";
    fixpackdate = ereg_replace(pattern:'^([0-9]+)-[0-9]+$', replace:"\1", string:fixpackdate);
    if (int(fixpackdate) < fixdate)  vuln = TRUE;
  }
}
else if (version =~ "^9\.0\.0( .*)?$")
{
  # Check the fixpack timestamp
  if (isnull(fixpackdate)) vuln = TRUE;
  else
  {
    fixdate = "20131201";
    fixpackdate = ereg_replace(pattern:'^([0-9]+)-[0-9]+$', replace:"\1", string:fixpackdate);
    if (int(fixpackdate) < fixdate) vuln = TRUE;
  }
}

if (vuln)
{
  port = get_kb_item('SMB/transport');
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path                    : ' + path +
      '\n  Installed version       : ' + version;
    if (!isnull(fixpackdate))
    {
      report +=
        '\n  Installed Fix Pack date : ' + fixpackdate +
        '\n  Fixed Fix Pack date     : ' + fixdate + '\n';
    }
    else report += '\n  No Fix Packs have been applied.\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app_name, version, path);
