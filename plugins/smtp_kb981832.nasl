#
# (C) Tenable Network Security, Inc.
#

# nb: script_name() is too long for Nessus 2.x.
if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");


if (description)
{
  script_id(45517);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/07/11 22:13:38 $");

  script_cve_id("CVE-2010-0024", "CVE-2010-0025");
  script_bugtraq_id(39381);
  script_osvdb_id(63738, 63739);
  script_xref(name:"MSFT", value:"MS10-024");
  script_xref(name:"IAVB", value:"2010-B-0029");

  script_name(english:"MS10-024: Vulnerabilities in Microsoft Exchange and Windows SMTP Service Could Allow Denial of Service (981832) (uncredentialed check)");
  script_summary(english:"Checks the remote SMTP server is patched for KB981832");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote mail server may be affected by multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The installed version of Microsoft Exchange / Windows SMTP Service
is affected by at least one vulnerability :

  - Incorrect parsing of DNS Mail Exchanger (MX) resource
    records could cause the Windows Simple Mail Transfer
    Protocol (SMTP) component to stop responding until 
    the service is restarted. (CVE-2010-0024)

  - Improper allocation of memory for interpreting SMTP
    command responses may allow an attacker to read random 
    email message fragments stored on the affected server.
    (CVE-2010-0025)"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
and 2008 as well as Exchange Server 2000, 2003, 2007, and 2010 :

http://technet.microsoft.com/en-us/security/bulletin/MS10-024"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:exchange_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"SMTP problems");

  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");

  script_dependencie("smtpserver_detect.nasl", "doublecheck_std_services.nasl");
  script_require_ports("Services/smtp", 25);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");

last_vers = NULL;

function _vers_cmp(a,b)
{
 local_var i, c;

 a = split(a, sep:'.', keep:FALSE);
 c = b;
 b = split(b, sep:'.', keep:FALSE);
 last_vers = NULL;

 if ( max_index(a) != 4 || max_index(b) != 4 ) return 0; # ???

 for ( i = 0 ; i < 4; i ++ )
 {
   if ( int(a[i]) != int(b[i]) ) 
   {
	 if ( i < 3 ) return 0; # Only compare the maj version
  	 last_vers = c;
	 return int(a[i]) - int(b[i]);
   }
 } 
 return 0;
}


function vers_cmp(ref, version, min)
{
 if ( _vers_cmp(a:version, b:min) < 0 ) return 0;
 return _vers_cmp(a:version, b:ref);
}

port = get_service(svc:"smtp", default:25, exit_on_fail:TRUE);
if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");

banner = get_smtp_banner(port:port);
if ( ! banner ) exit(1, "Nessus failed to extract the greeting from the SMTP server on port "+port+".");
line = egrep(pattern:"^220 .* Microsoft ESMTP MAIL Service, Version: ([0-9.]+) ready at.*", string:banner);
if ( ! line ) exit(0, "The greeting from the SMTP server on port "+port+" does not look like Microsoft's SMTP service.");

version = chomp(ereg_replace(pattern:"^220 .* Microsoft ESMTP MAIL Service, Version: ([0-9.]+) ready at.*", string:line, replace:"\1"));

if ( 
     # Windows 2000
     vers_cmp(version:version, ref:"5.0.2195.7381", min:"5.0.2195.0") < 0 ||
     # Windows 2003, XP x64
     vers_cmp(version:version, ref:"6.0.3790.4675", min:"6.0.3790.0") < 0 ||
     # Windows XP SP2
     vers_cmp(version:version, ref:"6.0.2600.3680", min:"6.0.2600.0") < 0 ||
     # Windows XP SP3
     vers_cmp(version:version, ref:"6.0.2600.5949", min:"6.0.2600.5000") < 0 ||
     #Windows 2008
     vers_cmp(version:version, ref:"7.0.6001.18440", min:"7.0.6001.0") < 0 ||
     vers_cmp(version:version, ref:"7.0.6001.22648", min:"7.0.6001.22000") < 0 ||
     vers_cmp(version:version, ref:"7.0.6002.18222", min:"7.0.6002.0") < 0 ||
     vers_cmp(version:version, ref:"7.0.6002.22354", min:"7.0.6002.22000") < 0 ||
     #Windows 2008 R2
     vers_cmp(version:version, ref:"7.5.7600.16544", min:"7.5.7600.0") < 0 ||
     vers_cmp(version:version, ref:"7.5.7600.20660", min:"7.5.7600.20000") < 0)
{
  security_warning(port:port, extra:'\nThe remote version of the smtpsvc.dll is ' + version + ' versus ' + last_vers + '.');
  exit(0);
}
else exit(0, "The SMTP server on port "+port+" uses smtpsvc.dll "+version+" and hence is not affected.");
