#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57915);
  script_version("$Revision: 2.35 $");
  script_cvs_date("$Date: 2016/10/24 18:44:13 $");

  script_name(english:"OS Identification : SMTP");
  script_summary(english:"Determines the remote operating system based on its SMTP banner.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system based on its
SMTP banner.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system based on the
banner reported by the mail server running on it.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smtpserver_detect.nasl", "os_fingerprint_sinfp.nasl");
  script_exclude_keys("SMTP/wrapped");
  script_require_ports("Services/smtp", 25);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("smtp_func.inc");


# nb: looping through all SMTP servers avoids possibly issuing
#     multiple reports because of differences in the timestamps
#     in the initial banners.
kb_list = get_kb_list("Services/smtp");
if (isnull(kb_list)) ports = make_list();
else ports = make_list(kb_list);

foreach port (make_list(25, 587))
{
  if (service_is_unknown(port:port)) ports = add_port_in_list(list:ports, port:port);
}
if (max_index(ports) == 0) exit(0, "The host does not appear to have a listening SMTP server.");


# Identify unique banners.
alt_banners = make_array();
banners = make_list();
ports_with_banners = make_list();

timestamp_pat = "^(.+) (Sun|Mon|Tue|Wed|Thu|Fri|Sat), [0-9]?[0-9] (Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [12][0-9][0-9][0-9] [01][0-9]:[0-5][0-9]:[0-5][0-9] ([-+][0-9][0-9][0-9][0-9]|[A-Z][A-Z][A-Z])";

foreach port (sort(ports))
{
  if (!get_port_state(port)) continue;

  banner = get_smtp_banner(port:port);
  if (!banner) continue;
  banner = chomp(banner);

  ports_with_banners = make_list(ports_with_banners, port);

  # Ignore this banner, modulo the timestamp, if it's one we already
  # came across before for this host.
  match = eregmatch(pattern:timestamp_pat, string:banner);
  if (isnull(match)) alt_banner = banner;
  else alt_banner = match[1];
  if (alt_banners[alt_banner]++) continue;

  banners = make_list(banners, banner);
}
if (max_index(banners) == 0) exit(0, "Did not collect any SMTP banners.");


# nb: the SinFP fingerprint is used to adjust the confidence.
sinfp = get_kb_item("Host/OS/SinFP");
sinfp_fingerprint = get_kb_item("Host/OS/SinFP/Fingerprint");


default_confidence = 80;
default_type = 'general-purpose';
kb_base = "Host/OS/SMTP";              # nb: should *not* end with a slash


i = 0;
name       = make_array();             # nb: '$1' in the name is replaced by a match from the SMTP pattern
smtp_pat   = make_array();
confidence = make_array();
dev_type   = make_array();

########
# Debian
#
# eg, "ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge3"
#     "ESMTP Sendmail 8.13.4/8.13.4/Debian-3sarge1"
name[i]     = "Linux Kernel 2.4 on Debian 3.1 (sarge)";
smtp_pat[i] = "E?SMTP Sendmail 8\.13\.4/8\.13\.4/Debian-3sarge[0-9]+;";
dev_type[i] = "general-purpose";
i++;

########
# Debian
#
#     "ESMTP Sendmail 8.14.4/8.14.4/Debian-8"
name[i]     = "Linux Kernel 3.2 on Debian 8.0 (jessie)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-8;";
dev_type[i] = "general-purpose";
i++;

########
# Debian
#
#     "ESMTP Sendmail 8.14.4/8.14.4/Debian-4"
#     "ESMTP Sendmail 8.14.4/8.14.4/Debian-4+deb7u1;"
name[i]     = "Linux Kernel 3.2 on Debian 7.0 (wheezy)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-4[;+]";
dev_type[i] = "general-purpose";
i++;

########
# Debian
#
#     "ESMTP Sendmail 8.14.3/8.14.3/Debian-9.4"
name[i]     = "Linux Kernel 2.6 on Debian 6.0 (squeeze)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.3/8\.14\.3/Debian-9\.4;";
dev_type[i] = "general-purpose";
i++;

########
# HP-UX
name[i]     = "HP-UX B.$1";
smtp_pat[i] = "ESMTP Sendmail .+ [0-9]+\.[0-9]+\.[0-9]+ - Revision [0-9]+\.[0-9]+:: HP-UX([0-9]+\.[0-9]+) - ";
dev_type[i] = "general-purpose";
i++;

name[i]     = "HP-UX";
smtp_pat[i] = "ESMTP Sendmail [0-9]+\.[0-9]+\.[0-9]+ \(PH[A-Z][A-Z]_[0-9]+\)/[0-9]+\.[0-9]+\.[0-9]+;";
dev_type[i] = "general-purpose";
i++;

########
# IRIX
name[i]     = "IRIX $1";
smtp_pat[i] = "ESMTP Postfix \(IRIX[ /]([0-9]+(\.[0-9]+)+.+)\)";
dev_type[i] = "general-purpose";
i++;

########
# openSUSE
#
# eg, "ESMTP Sendmail 8.14.3/8.14.3/SuSE Linux 0.8; ..."
name[i]     = "Linux Kernel 2.6 on openSUSE 11";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.3/8\.14\.3/SuSE Linux 0\.8;";
dev_type[i] = "general-purpose";
i++;

name[i]     = 'Linux Kernel 2.6 on openSUSE 11.4\nLinux Kernel 2.6 on openSUSE 12.1';
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/SuSE Linux 0\.8;";
dev_type[i] = "general-purpose";
i++;

name[i]     = 'Linux Kernel 3.1 on openSUSE 12.1\nLinux Kernel 3.4 on openSUSE 12.2\nLinux Kernel 3.7 on openSUSE 12.3';
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.5/8\.14\.5/SuSE Linux 0\.8;";
dev_type[i] = "general-purpose";
i++;

name[i]     = 'Linux Kernel 3.11 on openSUSE 13.1';
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.7/8\.14\.7/SuSE Linux 0\.8;";
dev_type[i] = "general-purpose";
i++;

name[i]     = 'Linux Kernel 3.16 on openSUSE 13.2\nLinux Kernel 4.1 on openSUSE 42.1';
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.9/8\.14\.9/SuSE Linux 0\.8;";
dev_type[i] = "general-purpose";
i++;

########
# OpenVMS
#
# eg, "220 example.com V5.6-9, OpenVMS V8.3 Alpha ready at ..."
#     "220 example.com V5.3-18E, OpenVMS V7.2 VAX ready at ..."
name[i]     = "OpenVMS $1";
smtp_pat[i] = " V[0-9]+\.[0-9]+-[0-9]+[A-Z]?, OpenVMS V([0-9]+\.[0-9]+[^ ]*) (Alpha|VAX) ready at ";
dev_type[i] = "general-purpose";
i++;

########
# Solaris
name[i]     = "Solaris 10";
smtp_pat[i] = "E?SMTP Sendmail (8\.13\.8\+Sun/8\.13\.8|8\.14\.4\+Sun/8\.14\.4);";
dev_type[i] = "general-purpose";
i++;

name[i]     = "Solaris 8";
smtp_pat[i] = "E?SMTP Sendmail 8\.11\.7p3\+Sun/8\.11\.7;";
dev_type[i] = "general-purpose";
i++;

name[i]     = "Solaris 2.6";
smtp_pat[i] = "E?SMTP Sendmail 8\.8\.8\+Sun/8\.8\.8;";
dev_type[i] = "general-purpose";
i++;

name[i]     = "Solaris";
smtp_pat[i] = "E?SMTP Sendmail 8\..+Sun/8\.";
dev_type[i] = "general-purpose";
i++;

########
# Sophos Email Appliance
name[i]       = "Sophos Email Appliance $1";
smtp_pat[i]   = "E?SMTP Sophos Email Appliance v([0-9]+(\.[0-9]+)+)";
confidence[i] = 85;
dev_type[i]   = "embedded";
i++;

########
# Symantec Messaging Gateway
name[i]       = "Symantec Messaging Gateway";
smtp_pat[i]   = "E?SMTP Symantec Messaging Gateway";
confidence[i] = 80;
dev_type[i]   = "embedded";
i++;

# Ubuntu 16.10
#
# eg, "ESMTP Sendmail 8.15.2/8.15.2/Debian-4;..."
name[i]     = "Linux Kernel 4.8 on Ubuntu 16.10 (yakkety)";
smtp_pat[i] = "E?SMTP Sendmail 8\.15\.2/8\.15\.2/Debian-4;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu 16.04
#
# eg, "ESMTP Sendmail 8.14.9/8.14.9/Debian-4;..."
name[i]     = "Linux Kernel 4.4 on Ubuntu 16.04 (xenial)";
smtp_pat[i] = "E?SMTP Sendmail 8\.15\.2/8\.15\.2/Debian-3;";
dev_type[i] = "general-purpose";
i++;
########
# Ubuntu 15.10
#
# eg, "ESMTP Sendmail 8.14.9/8.14.9/Debian-4;..."
name[i]     = "Linux Kernel 4.2 on Ubuntu 15.10 (wily)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.9/8\.14\.9/Debian-4;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-8; ..."
name[i]     = "Linux Kernel 3.19 on Ubuntu 15.04 (vivid)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-8;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-7; ..."
name[i]     = "Linux Kernel 3.16 on Ubuntu 14.10 (utopic)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-7;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-4.1ubuntu1; ..."
name[i]     = "Linux Kernel 3.13 on Ubuntu 14.04 (trusty)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-4.1ubuntu[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-2.1ubuntu1; ..."
name[i]     = "Linux Kernel 3.11 on Ubuntu 13.10 (saucy)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-2\.1ubuntu[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-2.1ubuntu1; ..."
name[i]     = "Linux Kernel 3.8 on Ubuntu 13.04 (raring)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-2\.1ubuntu[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-2.1ubuntu1; ..."
name[i]     = "Linux Kernel 3.5 on Ubuntu 12.10 (quantal)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-2\.1ubuntu[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.14.4/Debian-2ubuntu2; ..."
name[i]     = "Linux Kernel 3.0 on Ubuntu 12.04 (precise)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-2ubuntu2[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.4/8.4.14/Debian-2ubuntu1; ..."
name[i]     = "Linux Kernel 2.6 on Ubuntu 11.04 (natty)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.4/8\.14\.4/Debian-2ubuntu1[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Ubuntu
#
# eg, "ESMTP Sendmail 8.14.3/8.14.3/Debian-9.1ubuntu1; ..."
name[i]     = "Linux Kernel 2.6 on Ubuntu 10.04 (lucid)";
smtp_pat[i] = "E?SMTP Sendmail 8\.14\.3/8\.14\.3/Debian-9\.1ubuntu1[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

# eg, "ESMTP Sendmail 8.13.5.20060308/8.13.5/Debian-3ubuntu1; ..."
#     "ESMTP Sendmail 8.13.5.20060308/8.13.5/Debian-3ubuntu1.1; ..."
name[i]     = "Linux Kernel 2.6 on Ubuntu 6.06 (dapper)";
smtp_pat[i] = "E?SMTP Sendmail 8\.13\.5\.20060308/8\.13\.5/Debian-3ubuntu1[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

# eg, "ESMTP Sendmail 8.13.4/8.13.4/Debian-3ubuntu0.1; ..."
name[i]     = "Linux Kernel 2.6 on Ubuntu 5.10 (breezy)";
smtp_pat[i] = "E?SMTP Sendmail 8\.13\.4/8\.13\.4/Debian-3ubuntu0[0-9.]*;";
dev_type[i] = "general-purpose";
i++;

########
# Windows
#
# eg, "Microsoft ESMTP MAIL Service, Version: 6.0.3790.3959 ready at ..."
# eg, "Microsoft ESMTP MAIL Service ready at ..."
name[i]     = "Microsoft Windows";
smtp_pat[i] = "Microsoft ESMTP MAIL Service(, Version: [0-9.]+)? ready at";
dev_type[i] = "general-purpose";
i++;


set_kb_item(name:kb_base+"/Fingerprint", value:join(banners, sep:'\\n'));

n = i;
foreach banner (banners)
{
  for (i=0; i<n; i++)
  {
    match = eregmatch(pattern:smtp_pat[i], string:banner);
    if (match)
    {
      name = name[i];
      if ("$1" >< name && match[1])
        name = str_replace(find:"$1", replace:match[1], string:name);

      if (confidence[i]) conf = confidence[i];
      else
      {
        conf = default_confidence;
        if ('\n' >< name) conf -= 5;
      }

      if (
        !isnull(sinfp) &&
        !isnull(sinfp_fingerprint) &&
        !egrep(pattern:"P4:[0-9].+p=[0-9]+R", string:sinfp_fingerprint)
      )
      {
        flag = FALSE;
        foreach os (split(sinfp, keep:FALSE))
          if (os >< name)
          {
            flag = TRUE;
            break;
          }
        if (!flag) conf -= 20;
      }

      if (dev_type[i]) type = dev_type[i];
      else type = default_type;

      set_kb_item(name:kb_base, value:name);
      set_kb_item(name:kb_base+"/Confidence", value:conf);
      set_kb_item(name:kb_base+"/Type", value:type);

      exit(0);
    }
  }
}
if (max_index(ports_with_banners) == 1)
{
  port = join(ports_with_banners, sep:" ");
  exit(0, "Nessus was not able to identify the OS from its SMTP service banner from port "+port+".");
}
else exit(0, "Nessus was not able to identify the OS from its SMTP service banners from ports "+join(ports_with_banners, sep:" / ")+".");
