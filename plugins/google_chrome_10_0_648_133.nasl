#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52657);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/11/13 21:35:39 $");

  script_cve_id("CVE-2011-1290");
  script_bugtraq_id(46849);
  script_osvdb_id(71182);
  script_xref(name:"Secunia", value:"43748");

  script_name(english:"Google Chrome < 10.0.648.133 Code Execution");
  script_summary(english:"Checks version number of Google Chrome");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains a web browser that is affected by a code
execution vulnerability.");

  script_set_attribute(attribute:"description", value:
"The version of Google Chrome installed on the remote host is earlier
than 10.0.648.133.  Such versions are reportedly affected by a memory
corruption vulnerability in style handling.

By tricking a user into opening a specially crafted web page, a remote
unauthenticated attacker could execute arbitrary script code on the
host subject to the privileges of the user running the affected
application.");

  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d5960d07");
  script_set_attribute(attribute:"solution", value:"Upgrade to Google Chrome 10.0.648.133 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:google:chrome");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencies("google_chrome_installed.nasl");
  script_require_keys("SMB/Google_Chrome/Installed");

  exit(0);
}

include("google_chrome_version.inc");

get_kb_item_or_exit("SMB/Google_Chrome/Installed");

installs = get_kb_list("SMB/Google_Chrome/*");
google_chrome_check_version(installs:installs, fix:'10.0.648.133', severity:SECURITY_HOLE);
