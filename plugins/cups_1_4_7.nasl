#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56007);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");

  script_cve_id("CVE-2011-2896");
  script_bugtraq_id(49148);
  script_osvdb_id(74539);

  script_name(english:"CUPS < 1.4.7 'gif_read_lzw' Buffer Overflow");
  script_summary(english:"Checks CUPS server version");

  script_set_attribute(attribute:"synopsis", value:
"The remote print service is affected by a buffer overflow
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of CUPS installed on the remote
host is earlier than 1.4.7.

There is a boundary error in the function 'gif_read_lzw' in the file
'filter/image-gif.c' that can allow an attacker to cause a heap-based
buffer overflow via specially crafted gif images.");
  script_set_attribute(attribute:"see_also", value:"http://www.cups.org/articles.php?L628");
  script_set_attribute(attribute:"see_also", value:"https://github.com/apple/cups/issues/3867");
  script_set_attribute(attribute:"solution", value:"Upgrade to CUPS version 1.4.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/06/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/29");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:cups");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cups_1_3_5.nasl");
  script_require_keys("www/cups", "Settings/ParanoidReport");
  script_require_ports("Services/www", 631);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:631, embedded:TRUE);
get_kb_item_or_exit("www/"+port+"/cups/running");

version = get_kb_item_or_exit("cups/"+port+"/version");
source  = get_kb_item_or_exit("cups/"+port+"/source");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

if (version =~ "^(1|1\.4)($|[^0-9rb.])") audit(AUDIT_VER_NOT_GRANULAR, "CUPS", port, version);

if (
  version =~ "^1\.[0-3]($|[^0-9])" ||
  version =~ "^1\.4\.[0-6]($|[^0-9.])" ||
  version =~ "^1\.4(rc|b)"
)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Version source    : ' + source +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 1.4.7\n';

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "CUPS", port, version);
