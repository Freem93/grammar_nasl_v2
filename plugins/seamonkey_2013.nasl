#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52769);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/12/14 20:22:12 $");

  script_name(english:"SeaMonkey < 2.0.13 Invalid HTTP Certificates");
  script_summary(english:"Checks version of SeaMonkey");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a web browser with an out-of-date
SSL certificate blacklist.");
  script_set_attribute(attribute:"description",value:
"The installed version of SeaMonkey is earlier than 2.0.13. Such
versions have an out-of-date SSL certificate blacklist. 

A certificate authority (CA) has revoked a number of fraudulent SSL
certificates for several prominent public websites.  

If an attacker can trick someone into using the affected browser and
visiting a malicious site using one of the fraudulent certificates, he
may be able to fool that user into believing the site is a legitimate
one.  In turn, the user could send credentials to the malicious site
or download and install applications.");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-11.html");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9c7baa99");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b8fdcaa8");
  script_set_attribute(attribute:"solution", value:"Upgrade to SeaMonkey 2.0.13 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:seamonkey");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("SeaMonkey/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/SeaMonkey/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "SeaMonkey");

mozilla_check_version(installs:installs, product:'seamonkey', fix:'2.0.13', severity:SECURITY_WARNING);