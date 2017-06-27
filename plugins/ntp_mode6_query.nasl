#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97861);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/03/21 16:09:39 $");

  script_name(english:"Network Time Protocol (NTP) Mode 6 Scanner");
  script_summary(english:"NTP responds to mode 6 queries.");

  script_set_attribute(attribute:"synopsis", value:
"The remote NTP server responds to mode 6 queries.");
  script_set_attribute(attribute:"description", value:
"The remote NTP server responds to mode 6 queries. Devices that respond
to these queries have the potential to be used in NTP amplification
attacks. An unauthenticated, remote attacker could potentially exploit
this, via a specially crafted mode 6 query, to cause a reflected
denial of service condition.");
  script_set_attribute(attribute:"see_also", value:"https://ntpscan.shadowserver.org");
  script_set_attribute(attribute:"solution", value:
 "Restrict NTP mode 6 queries.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:N/A:L");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("ntp_open.nasl");
  script_require_keys("Services/udp/ntp");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"ntp", default:123);
res = get_kb_item("NTP/mode6_response");

if (empty_or_null(res)) exit(0, "Host does not respond to NTP Mode 6 queries.");
report = '\n  Nessus elicited the following response from the remote' +
         '\n  host by sending an NTP mode 6 query :' +
         '\n\n\'' + res + '\'';
security_report_v4(port:port, proto:"udp", extra:report, severity:SECURITY_WARNING);
