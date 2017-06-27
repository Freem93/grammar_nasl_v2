#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52768);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:52:57 $");

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.9 Invalid HTTP Certificates");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client with an out-of-date
SSL certificate blacklist.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.9.  Such
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
  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.9 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/23");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.9', min:'3.1.0', severity:SECURITY_WARNING);