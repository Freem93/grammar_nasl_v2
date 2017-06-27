#
# (C) Tenable Network Security, Inc.
#


# This plugin will not work with Nessus < version 4
if ( NASL_LEVEL < 3000 ) exit(0);
if (!defined_func("bpf_open")) exit(1, "bpf_open() is not defined.");

include("compat.inc");

if (description)
{
  script_id(45579);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/09 15:44:47 $");

  script_cve_id("CVE-2010-1152");
  script_bugtraq_id(39577);
  script_osvdb_id(63600);
  script_xref(name:"Secunia", value:"39306");

  script_name(english:"memcached No Newline Memory Consumption DoS");
  script_summary(english:"Checks if server rejects suspicious looking requests");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote object store has a denial of service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of memcached on the remote host has a denial of service
vulnerability.  When processing a client request, the service
continually reads in new data, reallocating its input buffer until a
newline character is received.  This could result in excessive
memory consumption.

A remote attacker could exploit this to crash memcached."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.google.com/p/memcached/issues/detail?id=102"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://code.google.com/p/memcached/wiki/ReleaseNotes143"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to memcached 1.4.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"vuln_publication_date",value:"2009/10/27");
  script_set_attribute(attribute:"patch_publication_date",value:"2009/11/07");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("memcached_detect.nasl");
  script_require_ports("Services/memcached", 11211);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("raw.inc");

port = get_service(svc:'memcached', exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Can't open a socket on port "+port+".");

bpf = bpf_open('tcp and src host '+get_host_ip()+' and src port '+port);
send(socket:soc, data:crap(data:'\0', length:4096));
vuln = NULL;

for (i = 0; i < 4; i++)
{
  pkt = bpf_next(bpf:bpf);
  if (isnull(pkt)) break;

  pkt = substr(pkt, strlen(link_layer()), strlen(pkt)); # strip datalink layer 
  res = packet_split(pkt);    # parse TCP/IP layers
  flags = NULL;
  if (!isnull(res[1]))
  {
    res1 = res[1];
    if (!isnull(res["data"]))
    {
      data = res["data"];
      if (!isnull(data["th_flags"])) flags = data["th_flags"];
    }
  }

  # patched servers will make some sort of attempt to kill the connection
  if (flags && (flags & TH_FIN || flags & TH_RST))
  {
    vuln = FALSE;
    break;
  }
  else if (flags && flags & TH_ACK) vuln = TRUE;
}

bpf_close(bpf);
close(soc);

if (isnull(vuln)) exit(1, 'No data was received from port '+port+'.');
else if (vuln) security_warning(port);
else exit(0, 'The memcached server on port '+port+' is not affected.');
