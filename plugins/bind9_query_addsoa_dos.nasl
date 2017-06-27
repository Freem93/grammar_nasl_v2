#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25121);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2017/05/02 23:36:52 $");

  script_cve_id("CVE-2007-2241");
  script_bugtraq_id(23738);
  script_osvdb_id(34748);

  script_name(english:"ISC BIND < 9.4.1 / 9.5.0a4 query.c query_addsoa Function Recursive Query DoS");
  script_summary(english:"Checks version of BIND");

  script_set_attribute(attribute:"synopsis", value:"The remote name server is prone to a denial of service attack.");
  script_set_attribute(attribute:"description", value:
"The version of BIND installed on the remote host reportedly is
affected by a denial of service vulnerability that may be triggered
when handling certain sequences of recursive queries.");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bind-users&m=117781099030155&w=2");
  # https://kb.isc.org/article/AA-00919/0/CVE-2007-2241%3A-Sequence-of-queries-can-cause-a-recursive-nameserver-to-exit.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f6288c32");
  script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bind-announce&m=117798912418849&w=2" );
  script_set_attribute(attribute:"solution", value:"Either disable recursion or upgrade to BIND 9.4.1 / 9.5.0a4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/01");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:isc:bind");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"DNS");
  script_copyright(english:"This script is Copyright (C) 2007-2017 Tenable Network Security, Inc.");

  script_dependencies("bind_version.nasl");
  script_require_keys("bind/version", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ver = get_kb_item("bind/version");
if (ver && ver =~ "^9\.(4\.0[^0-9]?|5\.0a[1-3])")
  security_hole(port:53, proto:"udp");
