#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93650);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id(
    "CVE-2016-7406",
    "CVE-2016-7407",
    "CVE-2016-7408",
    "CVE-2016-7409"
  );
  script_bugtraq_id(
    92970,
    92972,
    92973,
    92974
  );
  script_osvdb_id(
    142291,
    142292,
    142293,
    142294
  );

  script_name(english:"Dropbear SSH Server < 2016.72 Multiple Vulnerabilities");
  script_summary(english:"Checks the remote SSH server type and version.");

  script_set_attribute(attribute:"synopsis", value:
"The SSH service running on the remote host is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version in its banner, Dropbear SSH
running on the remote host is prior to 2016.74. It is, therefore,
affected by the following vulnerabilities :

  - A format string flaw exists due to improper handling of
    string format specifiers (e.g., %s and %x) in usernames
    and host arguments. An unauthenticated, remote attacker
    can exploit this to execute arbitrary code with root
    privileges. (CVE-2016-7406)

  - A flaw exists in dropbearconvert due to improper
    handling of specially crafted OpenSSH key files. An
    unauthenticated, remote attacker can exploit this to
    execute arbitrary code. (CVE-2016-7407)

  - A flaw exists in dbclient when handling the -m or -c
    arguments in scripts. An unauthenticated, remote attacker
    can exploit this, via a specially crafted script, to
    execute arbitrary code. (CVE-2016-7408)

  - A flaw exists in dbclient or dropbear server if they are
    compiled with the DEBUG_TRACE option and then run using
    the -v switch. A local attacker can exploit this to
    disclose process memory. (CVE-2016-7409)");
  script_set_attribute(attribute:"see_also", value:"https://matt.ucc.asn.au/dropbear/CHANGES");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Dropbear SSH version 2016.74 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:matt_johnston:dropbear_ssh_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("ssh_detect.nasl");
  script_require_ports("Services/ssh", 22);

  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("misc_func.inc");

app         = "Dropbear SSH";
port        = get_service(svc:"ssh", exit_on_fail:TRUE);
orig_banner = get_kb_item_or_exit("SSH/banner/" + port);
banner      = get_backport_banner(banner:orig_banner);

if ("dropbear" >!< banner) audit(AUDIT_NOT_DETECT, app, port);
if (backported) audit(AUDIT_BACKPORT_SERVICE, port, app);

item = eregmatch(pattern:"dropbear_([0-9]+\.[0-9]+(\.[0-9]+)?)($|[^0-9])", string:banner);
if (!item) audit(AUDIT_SERVICE_VER_FAIL, app, port);
version = item[1];

#SSH version : SSH-2.0-dropbear_0.53.1
#SSH version : SSH-2.0-dropbear_2011.54
if (
  # Early
  version =~ "^0\."
  ||
  # 2000-2015
  version =~ "^20(0\d|1[1-5])\."
  ||
  # 2016.0-2016.73
  version =~ "^2016\.([0-6]\d|7[0-3])"
)
{
  report_items = make_array(
    "Version source", orig_banner,
    "Installed version", version,
    "Fixed version", "2016.74"
  );
  order = make_list("Version source", "Installed version", "Fixed version");
  report = report_items_str(report_items:report_items, ordered_fields:order);
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report);
}
else audit(AUDIT_LISTEN_NOT_VULN, app, port, version);
