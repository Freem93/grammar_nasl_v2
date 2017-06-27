#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 4400 ) exit(1, "'bpf_open()' first appeared in Nessus 4.4.0.");

include("compat.inc");

if (description)
{
  script_id(56693);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2017/02/16 21:23:29 $");

  script_name(english:"Dropbox Software Detection (uncredentialed check)");
  script_summary(english:"Listens for Dropbox broadcast messages");

  script_set_attribute(attribute:"synopsis",value:
"There is a file synchronization application on the remote host.");
  script_set_attribute(attribute:"description",value:
"Dropbox is installed on the remote host.  Dropbox is an application
for storing and synchronizing files between computers, possibly
outside the organization.");
  script_set_attribute(attribute:"see_also",value:"https://www.dropbox.com/");
  script_set_attribute(attribute:"solution", value:
"Ensure that use of this software agrees with your organization's
acceptable use and security policies.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:dropbox:dropbox");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_dependencies("dropbox_listen.nasl");
  script_copyright(english:"This script is Copyright (C) 2011-2017 Tenable Network Security, Inc.");
  exit(0);
}


include('global_settings.inc');
include('raw.inc');


data = get_global_kb_item(strcat("Dropbox/", get_host_ip()));
if ( isnull(data) && thorough_tests )
{
 if ( !islocalnet() ) exit(0, "The remote host is more than one hop away.");

 ll = link_layer();
 if ( isnull(ll) ) exit(1, "Could not find the link layer we are operating on.");

 bpf = bpf_open("udp and src port 17500 and dst port 17500 and src host " + get_host_ip() + " and dst host 255.255.255.255");
 if ( ! bpf ) exit(1, "Could not obtain a bpf.");

 res = bpf_next(bpf:bpf, timeout:30000); # wait 30 secs
 bpf_close(bpf);
 if ( res )
 {
  res = substr(res, strlen(ll), strlen(res) - 1);
  pkt = packet_split(res);
  payload = pkt[2];
  data = payload['data'];
 }
}

if ( !isnull(data) && "host_int" >< data )
  security_note(port:17500, extra:'\nThe remote DropBox server broadcasts the following data :\n' + data, proto:"udp" );
