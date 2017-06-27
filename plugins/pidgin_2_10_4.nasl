#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59317);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/05/16 14:22:06 $");

  script_cve_id("CVE-2012-2214", "CVE-2012-2318");
  script_bugtraq_id(53400, 53706);
  script_osvdb_id(81707, 81708);

  script_name(english:"Pidgin < 2.10.4 Multiple DoS Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
potentially affected by multiple denial of service vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.10.4 and is, therefore, potentially affected by the following 
issues :

  - An error exists in the file 'libpurple/proxy.c' that
    can allow certain file transfer requests to an invalid
    pointer to be dereferenced, leading to application 
    crashes. (CVE-2012-2214)

  - An error exists in the function
    'msn_message_parse_payload' in the file
    'libpurple/protocols/msn/msg.c' that can allow certain
    characters or character encodings to crash the
    application. (CVE-2012-2318)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=62");
  script_set_attribute(attribute:"see_also", value:"http://www.pidgin.im/news/security/?id=63");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.10.4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.10.4';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Pidgin", version, path);
