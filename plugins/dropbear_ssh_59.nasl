#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70545);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/05/29 04:24:09 $");

  script_cve_id("CVE-2013-4421", "CVE-2013-4434");
  script_bugtraq_id(62958, 62993);
  script_osvdb_id(98303, 98365);

  script_name(english:"Dropbear SSH Server < 2013.59 Multiple Vulnerabilities");
  script_summary(english:"Checks remote SSH server type and version");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote SSH service is affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its self-reported banner, the version of Dropbear SSH
running on this port is earlier than 2013.59.  As such, it is
potentially affected by multiple vulnerabilities :

  - A denial of service vulnerability caused by the way the
    'buf_decompress()' function handles compressed files.
    (CVE-2013-4421)

  - User-enumeration is possible due to a timing error when
    authenticating users. (CVE-2013-4434)"
  );
  script_set_attribute(attribute:"see_also", value:"https://matt.ucc.asn.au/dropbear/CHANGES");
  script_set_attribute(attribute:"see_also", value:"https://secure.ucc.asn.au/hg/dropbear/rev/0bf76f54de6f");
  script_set_attribute(attribute:"see_also", value:"https://secure.ucc.asn.au/hg/dropbear/rev/a625f9e135a4");
  script_set_attribute(attribute:"solution", value:"Upgrade to the Dropbear SSH 2013.59 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:matt_johnston:dropbear_ssh_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ssh", exit_on_fail:TRUE);

orig_banner = get_kb_item_or_exit("SSH/banner/" + port);
banner = get_backport_banner(banner:orig_banner);

# Make sure it's Dropbear.
if ("dropbear" >!< banner) audit(AUDIT_NOT_DETECT, "Dropbear SSH", port);

#backported = get_kb_item_or_exit('');
if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, "Dropbear SSH");

item = eregmatch(pattern:"dropbear_([0-9\.]+)", string:banner);
if (isnull(item)) audit(AUDIT_SERVICE_VER_FAIL, "Dropbear SSH", port);
version = item[1];

#SSH version : SSH-2.0-dropbear_0.53.1
#SSH version : SSH-2.0-dropbear_2011.54
if (
  version =~ "^0\.([0-4][0-9]+|5[0-3])($|[^0-9])" ||
  version =~ "^201[1-3]\.([0-4][0-9]|5[0-8])($|[^0-9])"
)
{
  if (report_verbosity > 0)
  {
    report = '\n  Version source    : ' + orig_banner +
             '\n  Installed version : ' + version +
             '\n  Fixed version     : 2013.59\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_LISTEN_NOT_VULN, "Dropbear SSH", port, version);
