#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70260);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/05/16 14:02:52 $");

  script_cve_id("CVE-2013-0534");
  script_bugtraq_id(60536);
  script_osvdb_id(94423);

  script_name(english:"IBM Lotus Sametime Connect Client Password Disclosure");
  script_summary(english:"Checks version of IBM Lotus Sametime Connect Client");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a chat client installed that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of IBM Lotus Sametime Connect installed on the remote
Windows host is potentially affected by an information disclosure
vulnerability.  A flaw in the application causes client passwords to be
stored in the clear on the client's memory.");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21635218");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_sametime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("lotus_sametime_connect_installed.nasl");
  script_require_keys("SMB/IBM Lotus Sametime Client/Path", "SMB/IBM Lotus Sametime Client/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Version');
path    = get_kb_item_or_exit('SMB/IBM Lotus Sametime Client/Path');
fixpackdate = get_kb_item('SMB/IBM Lotus Sametime Client/fixpackdate');

# 8.5.1 and 8.5.2 are affected
vuln = FALSE;
fixdate = 20130616;

if (version =~ '^8\\.5\\.[12][^0-9]')
{
  # Check the fixpack timestamp
  if (isnull(fixpackdate)) vuln = TRUE;
  else
  {
    fixpackdate = ereg_replace(pattern:'^([0-9]+)-[0-9]+$', replace:"\1", string:fixpackdate);
    if (int(fixpackdate) < fixdate)
      vuln = TRUE;
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
      if (fixpackdate)
      {
        report +=
          '\n  Installed Fix Pack date : ' + fixpackdate +
         '\n  Fixed Fix Pack date     : 20130616\n';
      }
      else
        report += '\n  No Fix Packs have been applied.\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
    exit(0);
  }
}

audit(AUDIT_INST_PATH_NOT_VULN, 'IBM Lotus Sametime Connect', version, path);
