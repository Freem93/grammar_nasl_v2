#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90027);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/01 13:14:18 $");

  script_cve_id("CVE-2016-3116");
  script_osvdb_id(135770);

  script_name(english:"Dropbear SSH Server < 2016.72 xauth Command Injection");
  script_summary(english:"Checks remote SSH server type and version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote SSH service is affected by a command injection
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version in the banner, the version of
Dropbear SSH running on the remote host is prior to 2016.72. It is,
therefore, affected by a command injection vulnerability when X11
Forwarding is enabled, due to improper sanitization of X11
authentication credentials. An authenticated, remote attacker can
exploit this to execute arbitrary xauth commands on the remote host.

Note that X11 Forwarding is not enabled by default.");
  script_set_attribute(attribute:"see_also", value:"https://matt.ucc.asn.au/dropbear/CHANGES");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2016/Mar/47");
  # https://github.com/mkj/dropbear/commit/18681875e30e1ea251914417829fdbb50534c9ba
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c1e20657");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dropbear SSH version 2016.72 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/18");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:matt_johnston:dropbear_ssh_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_keys("Settings/ParanoidReport");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = "Dropbear SSH";
port = get_service(svc:"ssh", exit_on_fail:TRUE);

orig_banner = get_kb_item_or_exit("SSH/banner/" + port);
banner = get_backport_banner(banner:orig_banner);

# Make sure it's Dropbear.
if ("dropbear" >!< banner) audit(AUDIT_NOT_DETECT, "Dropbear SSH", port);

if (backported) audit(AUDIT_BACKPORT_SERVICE, port, "Dropbear SSH");

item = eregmatch(pattern:"dropbear_([0-9]+\.[0-9]+(\.[0-9]+)?)($|[^0-9])", string:banner);
if (isnull(item)) audit(AUDIT_SERVICE_VER_FAIL, "Dropbear SSH", port);
version = item[1];

#SSH version : SSH-2.0-dropbear_0.53.1
#SSH version : SSH-2.0-dropbear_2011.54
if (version =~ "^(0|201[1-5])\.")
{
  report_items = make_array(
    "Version source", orig_banner,
    "Installed version", version,
    "Fixed version", "2016.72"
  );
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:report_items, ordered_fields:order);
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Dropbear SSH", port, version);
