#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(10270);
  script_version ("$Revision: 1.27 $");
  script_cvs_date("$Date: 2015/08/24 14:25:06 $");

  script_cve_id("CVE-2000-0138");
  script_osvdb_id(295);

  script_name(english:"Stacheldraht Trojan Detection");
  script_summary(english:"Detects the presence of Stacheldraht.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a distributed denial of service (DDOS) agent
installed.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Stacheldraht, a trojan horse that can be
used to control your system or make it attack another network.

An ICMP ECHO reply was sent to the remote host with 'gesundheit!' and
an ID of 668. The host sent a reply with 'sicken\n' and an ID of 669.

If Paranoid is enabled, the plugin will only check for the ICMP ECHO
reply having ID 669.

It is very likely that this host has been compromised.");
  script_set_attribute(attribute:"see_also", value:"http://www.sans.org/security-resources/idfaq/stacheldraht.php");
  script_set_attribute(attribute:"solution", value:
"Restore your system from backups, and contact CERT and your local
authorities.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value: "2000/01/28");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english: "Backdoors");

  script_copyright(english:"This script is Copyright (C) 2000-2015 Tenable Network Security, Inc.");

  script_require_keys("Settings/ThoroughTests");
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("misc_func.inc");
include("obj.inc");

if ( TARGET_IS_IPV6 ) audit(AUDIT_ONLY_IPV4);
if ( islocalhost() ) audit(AUDIT_LOCALHOST);
if ( ! thorough_tests ) audit(AUDIT_THOROUGH);

src = this_host();

ip = forge_ip_packet(
       ip_v   : 4,
       ip_hl  : 5,
       ip_tos : 0,
       ip_id  : 0x1234,
       ip_len : 20,
       ip_off : 0,
       ip_p   : IPPROTO_ICMP,
       ip_src : src,
       ip_ttl : 0x40);

icmp = forge_icmp_packet(
         ip        : ip,
         icmp_type : 0,
         icmp_code : 0,
         icmp_seq  : 1,
         icmp_id   : 668,
         data      : "gesundheit!");

filter = "icmp and src host " + get_host_ip() + " and dst host " + this_host();

r = send_packet(icmp, pcap_active : TRUE, pcap_filter : filter);

vuln = FALSE;

if (r)
{
  type = get_icmp_element(icmp:r, element:"icmp_id");

  if (type == 669)
  {
    data = get_icmp_element(icmp:r, element:"data");

    report =
      '\nNessus was able to exploit the issue using the following ICMP ECHO reply :' +
      '\n' +
      '\n' + 'ECHO ( id = ' + get_icmp_element(icmp:icmp, element:"icmp_id") +
             '; data = ' + obj_rep(get_icmp_element(icmp:icmp, element:"data")) + ')' +
      '\n';
    snip = crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30);
    report +=
      '\nNessus confirmed this by examining ICMP traffic and looking for the' +
      '\nappropriate data in the ICMP ECHO reply. Below is the response :' +
      '\n\n' + snip +
      '\n' + 'ECHO ( id = ' + get_icmp_element(icmp:r, element:"icmp_id") +
             '; data = ' + obj_rep(data) + ')' +
      '\n' + snip +
      '\n';

    if (report_paranoia < 2)
    {
      if ('sicken\n' >< data)
        vuln = TRUE;
    }
    else if (report_paranoia == 2)
      vuln = TRUE;
  }
}

if(vuln)
{
  if(report_verbosity > 0)
  {
    report =
      '\nNessus was able to exploit the issue using the following ICMP ECHO reply :' +
      '\n' +
      '\n' + 'ECHO ( id = ' + get_icmp_element(icmp:icmp, element:"icmp_id") +
             '; data = ' + obj_rep(get_icmp_element(icmp:icmp, element:"data")) + ')' +
      '\n';
    snip = crap(data:'-', length:30) + ' snip ' + crap(data:'-', length:30);
    report +=
      '\nNessus confirmed this by examining ICMP traffic and looking for the' +
      '\nappropriate data in the ICMP ECHO reply. Below is the response :' +
      '\n\n' + snip +
      '\n' + 'ECHO ( id = ' + get_icmp_element(icmp:r, element:"icmp_id") +
             '; data = ' + obj_rep(data) + ')' +
      '\n' + snip +
      '\n';

    security_hole(port: 0, extra: report);
  }
  else security_hole(port: 0);
}
else audit(AUDIT_HOST_NOT, "affected");
