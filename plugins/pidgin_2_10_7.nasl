#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(64670);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2014/05/20 10:48:34 $");

  script_cve_id(
    "CVE-2013-0271",
    "CVE-2013-0272",
    "CVE-2013-0273",
    "CVE-2013-0274"
  );
  script_bugtraq_id(57951, 57952, 57954);
  script_osvdb_id(90231, 90232, 90233, 90234);

  script_name(english:"Pidgin < 2.10.7 Multiple Vulnerabilities");
  script_summary(english:"Does a version check");

  script_set_attribute(
    attribute:"synopsis",
    value:
"An instant messaging client installed on the remote Windows host is
affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Pidgin installed on the remote host is earlier than
2.10.7.  It is, therefore, potentially affected by the following
vulnerabilities :

  - An error exists related to the 'MXit' plugin and
    the saving of images that could allow arbitrary files
    to be overwritten. (CVE-2013-0271)

  - A stack-based buffer overflow  exists in the function
    'mxit_cb_http_read' in the file
    'libpurple/protocols/mxit/http.c' that could allow
    arbitrary code execution when handling certain HTTP
    headers. (CVE-2013-0272)

  - An error exists in the function 'mw_prpl_normalize' in
    the file 'libpurple/protocols/sametime/sametime.c' that
    could allow denial of service attacks when handling
    user IDs longer than 4096 bytes. (CVE-2013-0273)

  - Errors exist in the functions
    'upnp_parse_description_cb',
    'purple_upnp_discover_send_broadcast',
    'looked_up_public_ip_cb', 'looked_up_internal_ip_cb',
    'purple_upnp_set_port_mapping', and
    'purple_upnp_remove_port_mapping' in the file
    'libpurple/upnp.c' that could allow denial of service
    attacks when handling certain UPnP response messages.
    (CVE-2013-0274)"
  );
  script_set_attribute(attribute:"see_also", value:"http://hg.pidgin.im/pidgin/main/log/ad7e7fb98db3");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=65");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=66");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=67");
  script_set_attribute(attribute:"see_also", value:"http://pidgin.im/news/security/?id=68");
  script_set_attribute(attribute:"solution", value:"Upgrade to Pidgin 2.10.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:pidgin:pidgin");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("pidgin_installed.nasl");
  script_require_keys("SMB/Pidgin/Version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

path = get_kb_item_or_exit("SMB/Pidgin/Path");
version = get_kb_item_or_exit("SMB/Pidgin/Version");
fixed_version = '2.10.7';

if (ver_compare(ver:version, fix:fixed_version, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  if (report_verbosity > 0)
  {
    report =
      '\n  Path               : ' + path +
      '\n  Installed version  : ' + version +
      '\n  Fixed version      : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
else audit(AUDIT_INST_PATH_NOT_VULN, "Pidgin", version, path);
