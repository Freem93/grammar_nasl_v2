#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31119);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/23 20:31:33 $");

  script_cve_id("CVE-2008-0858", "CVE-2008-0859", "CVE-2008-0860");
  script_bugtraq_id(27868);
  script_osvdb_id(42124, 42125, 42126);
  script_xref(name:"Secunia", value:"29021");

  script_name(english:"Kerio MailServer < 6.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks version of KMS services");

 script_set_attribute(attribute:"synopsis", value:
"The remote mail server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Kerio MailServer, a commercial mail server
available for Windows, Linux, and Mac OS X platforms. 

According to its banner, the installed version of Kerio MailServer is
affected by several issues :

  - There is a possible buffer overflow in the Visnetic
    antivirus plug-in.

  - There is an as-yet unspecified security issue with NULL
    DACL in the AVG plug-in.

  - Memory corruption is possible during uudecode decoding." );
 script_set_attribute(attribute:"see_also", value:"http://www.kerio.com/kms_history.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Kerio MailServer 6.5.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94, 399);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:kerio:kerio_mailserver");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("kerio_kms_641.nasl");
  script_require_keys("kerio/port");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item('kerio/port');
if (isnull(port)) exit(1, "The 'kerio/port' KB item is missing.");

service = get_kb_item('kerio/'+port+'/service');
ver = get_kb_item('kerio/'+port+'/version');
display_ver = get_kb_item('kerio/'+port+'/display_version');

# There's a problem if the version is < 6.5.0.
iver = split(ver, sep:'.', keep:FALSE);
for (i=0; i<max_index(iver); i++)
  iver[i] = int(iver[i]);

fix = split("6.5.0", sep:'.', keep:FALSE);
for (i=0; i<max_index(fix); i++)
  fix[i] = int(fix[i]);

for (i=0; i<max_index(iver); i++)
  if ((iver[i] < fix[i]))
  {
    if (report_verbosity)
    {
      report = string(
        "\n",
        "According to its ", service, " banner, the remote host is running Kerio\n",
        "MailServer version ", display_ver, ".\n"
      );
      security_hole(port:port, extra:report);
    }
    else security_hole(port);

    exit(0);
    # never reached
  }
  else if (iver[i] > fix[i])
    break;

exit(0, 'Kerio MailServer '+display_ver+' is not affected.');
