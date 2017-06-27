#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40986);
  script_version("$Revision: 1.8 $");

  script_cve_id("CVE-2009-3025", "CVE-2009-3026");
  script_bugtraq_id(36367, 36368);
  script_osvdb_id(57521, 57522);

  script_name(english:"Pidgin < 2.6.1 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute( attribute:"synopsis", value:
"The remote host has an instant messaging client that is affected by 
multiple vulnerabilities."  );
  script_set_attribute( attribute:"description", value:
"The version of Pidgin installed on the remote host is earlier than
2.6.1.  Such versions are reportedly affected by one or more of
following issues :

  - The Yahoo protocol plugin may crash when receiving an IM
    from any user that contains a URL. (CVE-2009-3025)

  - The XMPP protocol plugin can be tricked into establishing
    an insecure connection by a malicious man-in-the-middle by 
    causing libpurple to use the older IQ-based login and then
    not offering TLS/SSL. (CVE-2009-3026)
"  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=36"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://pidgin.im/news/security/?id=35"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Pidgin 2.6.1 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(310);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/09/11"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/22"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/15"
  );
 script_cvs_date("$Date: 2011/08/18 21:56:06 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}


include("global_settings.inc");


version = get_kb_item("SMB/Pidgin/Version");
if (isnull(version)) exit(1, "The 'SMB/Pidgin/Version' KB item is missing.");

ver_fields = split(version, sep:'.', keep:FALSE);
major = int(ver_fields[0]);
minor = int(ver_fields[1]);
rev = int(ver_fields[2]);

# Versions < 2.6.1 are affected
if (
  major < 2 ||
  (major == 2 && minor < 6) ||
  (major == 2 && minor == 6 && rev < 1)
)
{
  port = get_kb_item("SMB/transport");

  if(report_verbosity > 0)
  {
    report = string(
      "\n",
      "  Installed version  : ", version, "\n",
      "  Should be at least : 2.6.1\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "Version " + version + " is not affected.");

