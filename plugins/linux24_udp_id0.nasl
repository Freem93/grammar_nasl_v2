#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17841);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/11/19 01:42:51 $");

  script_cve_id("CVE-2002-0510");
  script_bugtraq_id(4314);
  script_osvdb_id(9587);

  script_name(english:"Linux Kernel UDP Implementation IP Identification Field Remote OS Disclosure");
  script_summary(english:"Looks at id identification field in UDP responses");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote operating system can be identified based on its UDP
implementation."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host appears to be run a version of the Linux kernel that
sends UDP responses in which the IP identification field is constant and
equal to zero (0).

With this information, an attacker could mount further, more targeted
attacks against this host.

Note that RedHat does not consider this a security issue as there are
many ways to identify or fingerprint a Linux host."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2002/Mar/289"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.redhat.com/security/data/cve/CVE-2002-0510.html"
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None" );

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/20");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:linux:kernel");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_require_keys("Settings/PCI_DSS");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("snmp_func.inc");


if (!get_kb_item("Settings/PCI_DSS")) audit(AUDIT_PCI);


# nb: max number of requests to make. This should be great enough to
#     be reasonably sure we didn't get an id field of 0 by chance and
#     allow for some fragmented packets.
tries = 5;

community = get_kb_item("SNMP/community");
if (community)
{
  port = get_kb_item("SNMP/port");
  if (!port) port = 161;
  if (get_udp_port_state(port))
  {
    soc = open_sock_udp(port);
    if (soc)
    {
      filter = "src host " + get_host_ip() + " and src port " + port + " and dst port " + get_source_port(soc) + " and udp";

      oid = "1.3.6.1.2.1.1.1.0";
      timeout = 2;

      seq = make_list(
        ber_put_oid (oid:oid),
        ber_put_null()
      );
      seq = make_list(ber_put_sequence(seq:seq));
      req =  ber_put_int (i:snmp_request_id)          + # Request Id
             ber_put_int (i:0)                        + # Error Status: NO ERROR (0)
             ber_put_int (i:0)                        + # Error Index (0)
             ber_put_sequence (seq:seq);                # Object Identifier

      req =  ber_put_int (i:SNMP_VERSION)             + # version
             ber_put_octet_string (string:community)  + # community string
             ber_put_get_pdu (pdu:req);                 # PDU type

      req =  ber_put_sequence(seq:make_list(req));

      # Check several times
      count = 0;
      for (i=0; i<tries; i++)
      {
        send(socket:soc, data:req);
        res = send_capture(socket:soc, data:req, pcap_filter:filter);
        if (isnull(res)) break;

        # Look at non-fragmented packets.
        off = get_ip_element(ip:res, element:"ip_off");
        if ((off & (~0x4000)) == 0)
        {
          # Check the id.
          id = get_ip_element(ip:res, element:"ip_id");
          if (id == 0)
          {
            count++;
            if (count > 2)
            {
              security_note(port:port, proto:"udp");
              exit(0);
            }
          }
          else audit(AUDIT_HOST_NOT, 'affected');
        }
      }
    }
  }
}

audit(AUDIT_HOST_NOT, 'affected');
