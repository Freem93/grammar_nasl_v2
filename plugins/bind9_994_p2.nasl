#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71940);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/11/23 20:31:31 $");

  script_cve_id("CVE-2014-0591");
  script_bugtraq_id(64801);
  script_osvdb_id(101973);

  script_name(english:"ISC BIND 9 NSEC3-Signed Zone Handling DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:
"The remote name server may be affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote installation
of BIND is affected by a denial of service vulnerability.  This issue
exists due to the handling of queries for NSEC3-signed zones related to
the memcpy() function in the 'name.c' file on authoritative nameservers. 

Note that Nessus has only relied on the version itself and has not
attempted to determine whether or not the install is actually
affected.");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01078");
  script_set_attribute(attribute:"see_also", value:"https://kb.isc.org/article/AA-01085");
  # http://ftp.isc.org/isc/bind9/9.6-ESV-R10-P2/RELEASE-NOTES-BIND-9.6-ESV-R10-P2.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a4865c67");
  # http://ftp.isc.org/isc/bind9/9.6-ESV-R11/RELEASE-NOTES-BIND-9.6-ESV-R11
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fb52a286");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.8.6-P2/RELEASE-NOTES-BIND-9.8.6-P2.txt");
  # http://ftp.isc.org/isc/bind9/9.8.7/RELEASE-NOTES-BIND-9.8.7
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d2ca0d76");
  script_set_attribute(attribute:"see_also", value:"http://ftp.isc.org/isc/bind9/9.9.4-P2/RELEASE-NOTES-BIND-9.9.4-P2.txt");
  # http://ftp.isc.org/isc/bind9/9.9.5/RELEASE-NOTES-BIND-9.9.5
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?1c70dc0f");
  script_set_attribute(attribute:"solution", value:
"Upgrade to BIND version 9.9.5 / 9.9.4-P2 / 9.8.7 / 9.8.6-P2 / 9.6-ESV-R11 / 9.6-ESV-R10-P2 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/14");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");


ver = get_kb_item_or_exit("bind/version");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# Check whether BIND is vulnerable, and recommend an upgrade.
# Vuln BIND 9.6.0-9.6-ESV-R10-P1, 9.7.0-9.7.7, 9.8.0-9.8.6-P1, 9.9.0-9.9.4-P1
# Vuln BIND Development : 9.6-ESV-R11b1, 9.8.7b1, 9.9.5b1
fix = NULL;

if (
  # Vuln 9.6.0-9.6-ESV-R10-P1
  ver =~ "^9\.6(\.|(-ESV($|-R([0-9]($|[^0-9])|10(b1|rc[12]|-P1)$))))" ||
  # Vuln 9.6-ESV-R11b1
  ver ==  "9.6-ESV-R11b1"
)
  fix = '9.6-ESV-R11 / 9.6-ESV-R10-P2';
else if (ver =~ "^9\.7($|[^0-9])")
  # Vuln 9.7.0-9.7.7 (there is no 9.7.x fix; recommend higher upgrade)
  fix = '9.8.6-P2';
else if (
  # Vuln 9.8.0-9.8.6-P1
  ver =~ "^9\.8\.[0-5]($|[^0-9])" ||
  ver =~ "^9\.8\.6(b[1-2]|rc[1-2]|-P1)?$"
)
  fix = '9.8.6-P2';
else if (ver == "9.8.7b1")
  # Vuln 9.8.7b1
  fix = '9.8.7';
else if (
  # Vuln 9.9.0-9.9.4-P1
  ver =~ "^9\.9\.[0-3]($|[^0-9])" ||
  ver =~ "^9\.9\.4(b[1-2]|rc[1-2]|-P1)?$"
)
  fix = '9.9.4-P2';
else if (ver == "9.9.5b1")
  # Vuln 9.9.5b1
  fix = '9.9.5';
else if (
  # Subscription from DNSco
  # Vuln 9.9.3-S1 - 9.9.4-S1-P1
  (ver =~ "^9\.9\.[34]-S1($|-P1$)")
)
  fix = "9.9.4-S1-P2";
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
