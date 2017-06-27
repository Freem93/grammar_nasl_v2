#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70889);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/06/22 04:30:22 $");

  script_cve_id("CVE-2013-6230");
  script_bugtraq_id(63610);
  script_osvdb_id(99492);

  script_name(english:"ISC BIND 9 localnets ACL Security Bypass");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server is prone to a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND on Windows contains an ACL security bypass vulnerability because
the Winsock API does not properly support the 'SIO_GET_INTERFACE_LIST'
command for the netmask 255.255.255.255.  The netmask 255.255.255.255
will be translated to 0.0.0.0, which will match any IP address.  This
leads to IP address restrictions being bypassed. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01062/0/CVE-2013-6230");
  # https://kb.isc.org/article/AA-01063/0/CVE-2013-6230%3A-FAQ-and-Supplemental-Information.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b819444d");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01067");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01068");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01069/");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.6-ESV-R10-P1/CHANGES");
  # http://ftp.isc.org/isc/bind9/9.6-ESV-R11/RELEASE-NOTES-BIND-9.6-ESV-R11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb52a286");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.6-P1/CHANGES");
  # http://ftp.isc.org/isc/bind9/9.8.7/RELEASE-NOTES-BIND-9.8.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2ca0d76");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.4-P1/CHANGES");
  # http://ftp.isc.org/isc/bind9/9.9.5/RELEASE-NOTES-BIND-9.9.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c70dc0f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.5 / 9.9.4-P1 / 9.8.7 / 9.8.6-P1 / 9.6-ESV-R11 / 9.6-ESV-R10-P1
or later or refer to the vendor for a workaround.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/11/13");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl", "os_fingerprint.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

os = get_kb_item("Host/OS");
if (!os || "Windows" >!< os) audit(AUDIT_OS_NOT, "Windows");

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln BIND 9.6.0-9.6-ESV-R10-P1, 9.7.0-9.7.7, 9.8.0-9.8.6-P1, 9.9.0-9.9.4-P1
fix = NULL;

if (ver =~ "^9\.6(\.|(-ESV($|-R([0-9]($|[^0-9])|10(b[1]$|rc[12]$)))))")
  fix = '9.6-ESV-R11 / 9.6-ESV-R10-P1';
else if (ver =~ "^9\.7($|[^0-9])")
  # Vuln 9.7.0-9.7.7 (there is no 9.7.x fix; recommend higher upgrade)
  fix = '9.8.6-P1';
else if (
  # Vuln 9.8.0-9.8.6-P1
  ver =~ "^9\.8\.[0-5]($|[^0-9])" ||
  ver =~ "^9\.8\.6(b[1-2]|rc[1-2])?$"
)
  fix = '9.8.7 / 9.8.6-P1';
else if (
  # Vuln 9.9.0-9.9.4-P1
  ver =~ "^9\.9\.[0-3]($|[^0-9])" ||
  ver =~ "^9\.9\.4(b[1-2]|rc[1-2])?$"
)
  fix = '9.9.5 / 9.9.4-P1';
else if (
  # Subscription from DNSco
  # 9.9.3-S1
  (ver == "9.9.3-S1" || ver == "9.9.4-S1")
)
  fix = "9.9.4-S1-P1";
else
  audit(AUDIT_LISTEN_NOT_VULN, "BIND", 53, ver, "UDP");

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_warning(port:53, proto:"udp", extra:report);
}
else security_warning(port:53, proto:"udp");
