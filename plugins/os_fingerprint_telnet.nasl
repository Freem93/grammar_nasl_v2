#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29831);
  script_version("$Revision: 1.98 $");
  script_cvs_date("$Date: 2017/03/13 21:17:23 $");

  script_name(english:"OS Identification : Telnet");
  script_summary(english:"Determines the remote operating system from the telnet banner.");

  script_set_attribute(attribute:"synopsis", value:
"It was possible to identify the remote operating system based on its
telnet banner.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to identify the remote operating system based on the
telnet banner.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/01/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("telnetserver_detect_type_nd_version.nasl");
  script_require_ports("Services/telnet", 23);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("telnet_func.inc");

default_confidence = 51;

function check_banner()
{
  local_var banner, conf, line, match, os, res, version;
  local_var linux_kernel, pat, matches;

  banner = _FCT_ANON_ARGS[0];
  if (isnull(banner)) return NULL;

  res = make_array();
  if (
    "AIX" >< banner &&
    "telnet (" >< banner &&
    (
      "Copyright IBM Corporation" >< banner ||
      "Copyrights by IBM and by others" >< banner
    )
  )
  {
    os = "AIX";

    match = eregmatch(pattern:"AIX [Vv]ersion ([0-9][0-9.]*)", string:banner);
    if (!isnull(match)) os = os + " " + match[1];

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "general-purpose";

    return res;
  }
  else if (
    "IBM Virtual I/O Server" >< banner &&
    "login:" >< banner
  )
  {
    # nb: PowerVM supports IBM i, AIX, and Linux; the banner
    #     doesn't give us info on which is actually in use.
    os = "Virtual I/O Server on an IBM PowerVM";

    res["os"] = os;
    res["confidence"] = 71;
    res["type"] = "embedded";

    return res;
  }
  else if (
    (
      "IRIX (" >< banner ||
      "IRIX System V" >< banner
    ) &&
    "login:" >< banner
  )
  {
    os = "IRIX";

    res["os"] = os;
    res["confidence"] = 61;
    res["type"] = "general-purpose";

    return res;
  }
  else if ("SunOS 5" >< banner)
  {
    line = egrep(pattern:"SunOS 5\.[0-9]", string:banner);
    if (line && line != banner)
    {
      os = "Solaris";

      match = eregmatch(pattern:"SunOS 5\.([0-9]+).*", string:line);
      if (!isnull(match))
      {
        version = match[1];
        if (int(version) >= 7) os += " " + version;
        else os += " 2." + version;
      }

      res["os"] = os;
      res["confidence"] = 70;
      res["type"] = "general-purpose";

      return res;
    }
  }
  # eg,
  #   SCO OpenServer(TM) Release 5 (example.com) (ttyp4)
  else if ("SCO OpenServer(TM) Release" >< banner)
  {
    res["os"] = "SCO OpenServer";
    res["confidence"] = default_confidence;
    res["type"] = "general-purpose";

    return res;
  }
  else if ("Tru64 UNIX" >< banner)
  {
    os = "Tru64 UNIX";

    match = eregmatch(pattern:"Tru64 UNIX V([0-9][0-9.]+([A-Z](-[0-9]+)?)?).*", string:banner);
    if (!isnull(match)) os += " " + match[1];

    res["os"] = os;
    res["confidence"] = 80;
    res["type"] = "general-purpose";

    return res;
  }
  # FreeBSD; eg,
  #   FreeBSD/i386 (freebsd74.mlab) (ttyp0)
  else if ("FreeBSD/" >< banner)
  {
    res["os"] = "FreeBSD";
    res["confidence"] = default_confidence;
    res["type"] = "general-purpose";

    return res;
  }
  else if (
    egrep(pattern:"Serial Number .* MAC address", string:banner) &&
    "Software version " >< banner &&
    "Press Enter to go into Setup Mode, wait to close" >< banner
  )
  {
    res["os"] = "Modbus/TCP to RTU Bridge";
    res["confidence"] = 98;
    res["type"] = "embedded";

    return res;
  }
  # QNX Neutrino
  #   QNX Neutrino (localhost) (ttyp2)
  else if ("QNX Neutrino (" >< banner)
  {
    res["os"] = "QNX";
    res["confidence"] = 95;
    res["type"] = "embedded";

    return res;
  }
  else if (
    "CentOS " >< banner ||
    "Debian" >< banner ||
    "Fedora " >< banner ||
    "Linux Mandrake" >< banner ||
    "Red Hat Enterprise Linux " >< banner ||
    "Red Hat Linux " >< banner ||
    "SUSE" >< banner ||
    "SuSE" >< banner ||
    "Ubuntu " >< banner ||
    "Virtuozzo " >< banner ||
    "Caldera OpenLinux(TM)" >< banner ||
    egrep(pattern:"^Corel Linux/", string:banner) ||
    eregmatch(pattern:"^(Linux )?Kernel ([12]\.[0-6](\.[0-9A-Za-z.-]+))", string:chomp(banner)) ||
    egrep(pattern:"Kernel [0-9.\-]+\.fc\d\d\.(i686|i686\+PAE|x86_64) ", string:banner)
  )
  {
    # nb: raise default confidence for Linux distros, but not high
    #     enough to cause unsupported_operating_system.nasl to fire.
    default_confidence = 70;

    match = eregmatch(pattern:"^(Linux )?Kernel ([1-9][0-9]+\.[0-9]+(\.[0-9A-Za-z.-]+))", string:chomp(banner));
    if (!isnull(match)) linux_kernel = "Linux Kernel " + match[2];

    if ("Ubuntu " >< banner)
    {
      # Ubuntu 8.04.1
      # ubuntu login:
      line = egrep(pattern:"^Ubuntu ([4-9]|[1-9][0-9])\.([0-9]{2})(\.[0-9])? *$", string:banner);
      if (strlen(line) > 0)
      {
        if (!linux_kernel) linux_kernel = "Linux Kernel 2.6";

        res["os"] = linux_kernel + " on " + chomp(line);
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if ("CentOS " >< banner)
    {
      # CentOS release 4.6 (Final)
      # Kernel 2.6.9-67.0.15.EL on an i686
      line = egrep(pattern:"^CentOS( Linux)? release [1-6]\.[0-9] ", string:banner);
      if (strlen(line) > 0)
      {
        line = chomp(line);

        conf = 75;
        if (!linux_kernel)
        {
          if (line =~ "^CentOS( Linux)? release 7\.") linux_kernel = "Linux Kernel 3.10";
          else if (line =~ "^CentOS( Linux)? release [4-6]\.") linux_kernel = "Linux Kernel 2.6";
          else if (line =~ "^CentOS release [23]\.") linux_kernel = "Linux Kernel 2.4";
          else
          {
            linux_kernel = "Linux Kernel 2.6"; # Unrecognized distro?
            conf = 51; # back to lack of confidence
          }
        }

        res["os"] = linux_kernel + " on " + line;
        res["confidence"] = conf;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if ("Virtuozzo" >< banner)
    {
      line = egrep(pattern:"Kernel [0-9.\-]+\.vz\d\.[0-9.]+ on an (i686|i686\+PAE|x86_64)", string:banner);
      conf = default_confidence;
      if (strlen(line) > 0)
      {
        line = chomp(line);
        conf = 75;
        if (!linux_kernel)
        {
          # Virtuozzo 7.3
          if (line =~ "^Kernel [0-9.\-]+\.vz7\.20\.18 on an (i686|i686\+PAE|x86_64)")
          {
            linux_kernel = "Linux Kernel 3.10";
            line = "Virtuozzo 7.3";
          }
          # Virtuozzo 7.2
          if (line =~ "^Kernel [0-9.\-]+\.vz7\.15\.2 on an (i686|i686\+PAE|x86_64)")
          {
            linux_kernel = "Linux Kernel 3.10";
            line = "Virtuozzo 7.2";
          }
          else
          {
            matches = eregmatch(
              string:line,
              pattern:"^Kernel ([0-9]+\.[0-9]+)\.[0-9.\-]+\.vz(\d+)\."
            );
            if (matches)
            {
              linux_kernel = matches[1];
              line = matches[2];
              conf = 70;
            }
          }
        }
      }

      res["os"] = linux_kernel + " on " + line;
      res["confidence"] = conf;
      res["type"] = "general-purpose";

      return res;
    }
    else if (
      "Fedora " >< banner ||
      egrep(pattern:"Kernel [0-9.\-]+\.fc\d\d\.(i686|i686\+PAE|x86_64) ", string:banner)
    )
    {
      # Fedora release 8 (Werewolf)
      # Kernel 2.6.25.4-10.fc8 on an i686
      # login:
      line = egrep(pattern:"^Fedora (Core )?release [1-9][0-9]* ", string:banner);
      if (strlen(line) > 0)
      {
        line = chomp(line);
        if (!linux_kernel)
        {
          if (line =~ "^Fedora release 22") linux_kernel = "Linux Kernel 4.0";
          else if (line =~ "^Fedora release 21") linux_kernel = "Linux Kernel 3.17";
          else if (line =~ "^Fedora release 20") linux_kernel = "Linux Kernel 3.11";
          else if (line =~ "^Fedora release 19") linux_kernel = "Linux Kernel 3.9";
          else if (line =~ "^Fedora release 18") linux_kernel = "Linux Kernel 3.7";
          else if (line =~ "^Fedora release 17") linux_kernel = "Linux Kernel 3.3";
          else if (line =~ "^Fedora release 16") linux_kernel = "Linux Kernel 3.0";
          else if (line =~ "^Fedora (Core )? release 1 ") linux_kernel = "Linux Kernel 2.4";
          # Fedora Core 2 to release 15 is 2.6 Kernel
          else linux_kernel = "Linux Kernel 2.6";
        }

        res["os"] = linux_kernel + " on " + line;
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
      # New style; Fedora 23 and greater
      # Kernel 4.2.5-300.fc23.i686+PAE
      # Kernel 4.2.5-300.fc23.x86_64
      else if (egrep(pattern:"Kernel [0-9.\-]+\.fc\d\d\.(i686|i686\+PAE|x86_64) ", string:banner))
      {
        line = egrep(pattern:"Kernel [0-9.\-]+\.fc\d\d\.(i686|i686\+PAE|x86_64) ", string:banner);
        if (strlen(line) > 0)
        {
          line = chomp(line);
          if (!linux_kernel)
          {
            # Fedora 23
            if (line =~ "^Kernel [0-9.\-]+\.fc23\.(i686|i686\+PAE|x86_64)")
            {
              linux_kernel = "Linux Kernel 4.2";
              line = "Fedora release 23";
            }
            # Fedora 24
            if (line =~ "^Kernel [0-9.\-]+\.fc24\.(i686|i686\+PAE|x86_64)")
            {
              linux_kernel = "Linux Kernel 4.6";
              line = "Fedora release 24";
            }
            # Fedora 25
            if (line =~ "^Kernel [0-9.\-]+\.fc25\.(i686|i686\+PAE|x86_64)")
            {
              linux_kernel = "Linux Kernel 4.8";
              line = "Fedora release 25";
            }
          }
        }

        res["os"] = linux_kernel + " on " + line;
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if ("Red Hat Enterprise Linux " >< banner)
    {
      # Red Hat Enterprise Linux ES release 3 (Taroon Update 9)
      # Kernel 2.4.21-57.EL on an i686
      #
      # Red Hat Enterprise Linux Server release 5.2 (Tikanga)
      # Kernel 2.6.18-92.1.6.el5 on an i686
      pat = "^(Red Hat Enterprise Linux) [A-Za-z]+ release ([0-9.]+) ";
      line = egrep(pattern:pat, string:banner);
      if (strlen(line) > 0)
      {
        line = chomp(line);
        match = eregmatch(pattern:pat, string:line);
        if (!isnull(match))
        {
          if (!linux_kernel)
          {
            if (egrep(pattern:" release 7($|[^0-9])", string:banner)) linux_kernel = "Linux Kernel 3.10";
            else if (" release 3 " >< banner) linux_kernel = "Linux Kernel 2.4";
            else linux_kernel = "Linux Kernel 2.6";
          }

          res["os"] = linux_kernel + " on " + match[1] + " " + match[2];
          res["confidence"] = 71;
          res["type"] = "general-purpose";

          return res;
        }
      }
    }
    else if ("Red Hat Linux " >< banner)
    {
      # Red Hat Linux release 4.2 (Biltmore)
      # Kernel 2.0.30 on an i686
      line = egrep(string: banner, pattern: "^Red Hat Linux release [0-9.]+ " );
      if (strlen(line) > 0)
      {
        line = chomp(line);
        if (! linux_kernel)
        {
          if (line =~ " release (4\.2|5\.[0-2])") linux_kernel = "Linux Kernel 2.0";
          else if (line =~ " release (6\.[0-2]|7\.0)") linux_kernel = "Linux Kernel 2.2";
          else linux_kernel = "Linux Kernel 2.4";
        }

        res["os"] = linux_kernel + " on " + line;
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if ("Linux Mandrake" >< banner)
    {
      # Linux Mandrake release 5.2 (Leelo)
      # Linux Mandrake release 7.0 (Air)
      line = egrep(string: banner, pattern:"^Linux Mandrake release [5-9]\.[0-9]+ ");
      if (strlen(line) > 0)
      {
        version = ereg_replace(pattern:"^Linux Mandrake release ([5-9]\.[0-9]+) ", replace:"MDK\1", string:chomp(line));
        if (!linux_kernel)
        {
          if (version =~ "^MDK200[6-8]") linux_kernel = "Linux Kernel 2.6";
          else if (version =~ "^MDK10") linux_kernel = "Linux Kernel 2.6";
          else if (version =~ "^MDK[89]") linux_kernel = "Linux Kernel 2.4";
          else if (version =~ "^MDK[67]") linux_kernel = "Linux Kernel 2.2";
          else if (version =~ "^MDK5") linux_kernel = "Linux Kernel 2.0";
          else linux_kernel = "Linux Kernel 2.6";
        }

        res["os"] = linux_kernel + " on " + line;
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if ("Debian" >< banner)
    {
      # Debian GNU/Linux 4.0
      # Debian GNU/Linux 2.2
      line = egrep(string: banner, pattern: "^Debian GNU/Linux [1-9]\.[0-9]");
      if (strlen(line) > 0)
      {
        version = chomp(line) - "Debian GNU/Linux ";
        if (!linux_kernel)
        {
          if (version =~ "^(1\.|2\.[01])") linux_kernel = "Linux Kernel 2.0";
          else if (version == "2.2" || version == "3.0") linux_kernel = "Linux Kernel 2.2";
          else if (version == "3.1") linux_kernel = "Linux Kernel 2.4";
          else linux_kernel = "Linux Kernel 2.6";
        }

        res["os"] = linux_kernel + " on Debian " + version;
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if ("SUSE" >< banner || "SuSE" >< banner)
    {
      # Welcome to openSUSE 11.0 (X86-64) - Kernel 2.6.25.11-0.1-default (15).
      # No usable remote banner for very old SuSE - /etc/issue contains:
      # Welcome to S.u.S.E. Linux 5.1 - Kernel \r (\l)
      #
      # Welcome to SUSE Linux Enterprise Desktop 10 SP2 (i586) - Kernel %r (%t).
      # Welcome to SUSE Linux Enterprise Server 10 SP1 (i586) - Kernel 2.6.16.46-0.12-default (1).
      #
      # Welcome to SuSE Linux 9.3 (i586) - Kernel %r (%t).
      # Welcome to SuSE Linux 9.3 (i586) - Kernel 2.6.11.4-21.10-default (2).
      # Welcome to openSUSE Leap 42.1 - Kernel 4.1.12-1-default (1).
      line = egrep(pattern:'^Welcome to (open)?S[uU]SE ([A-Z][a-z]+ )*[0-9.]+( .*[\\("].*[\\)"])? - Kernel [0-9]', string:banner);
      match = NULL;
      if (strlen(line) > 0) match = eregmatch(pattern:" (open)?S[uU]SE ([A-Z][a-z]+ )*([0-9.]+) ", string:line);
      if (!isnull(match))
      {
        if ("opensuse" >< tolower(line)) os = "openSUSE";
        else os = "SuSE";

        version = match[3];
        if (! linux_kernel)
        {
          if (version =~ "^(9\.0|8\.|7\.[23])") linux_kernel = "Linux Kernel 2.4";
          else if (version =~ "^(7\.[01]|6[1-4])") linux_kernel = "Linux Kernel 2.2";
          else if (version =~ "^(6\.0|5\.)") linux_kernel = "Linux Kernel 2.0";
          else if (version =~ "^(9\.[1-3]|1[01]\.)") linux_kernel = "Linux Kernel 2.6";
          else if (version =~ "^12\.1($|[^0-9])") linux_kernel = "Linux Kernel 3.1";
          else if (version =~ "^12\.2($|[^0-9])") linux_kernel = "Linux Kernel 3.4";
          else if (version =~ "^12\.3($|[^0-9])") linux_kernel = "Linux Kernel 3.7";
          else if (version =~ "^13\.1($|[^0-9])") linux_kernel = "Linux Kernel 3.11";
          else if (version =~ "^13\.2($|[^0-9])") linux_kernel = "Linux Kernel 3.16";
          else if (version =~ "^42\.1($|[^0-9])") linux_kernel = "Linux Kernel 4.1";
          else linux_kernel = "Linux Kernel 2.6";
        }

        res["os"] = linux_kernel + " on " + os + " " + version;
        res["confidence"] = default_confidence;
        res["type"] = "general-purpose";

        return res;
      }
    }
    else if (egrep(pattern:"^Corel Linux/", string:banner))
    {
      # Corel Linux/Linux CorelLinux.localdomain
      if (! linux_kernel) linux_kernel = "Linux Kernel 2.2";

      res["os"] = linux_kernel + " on Corel Linux";
      res["confidence"] = default_confidence;
      res["type"] = "general-purpose";

      return res;
    }
    else if ("Caldera OpenLinux(TM)" >< banner)
    {
      os = "OpenLinux";

      if (!linux_kernel) linux_kernel = "Linux Kernel 2.2"; # Not sure but who cares? This distro has been defunct for many years

      # Caldera OpenLinux(TM)
      # Version 2.3
      # Copyright 1996-1999 Caldera Systems, Inc.
      line = egrep(pattern:"^Version +[12]\.[0-9]+", string:banner);
      if (strlen(line) > 0)
      {
        version = ereg_replace(pattern:"^Version +([12]\.[0-9]+)", replace:"\1", string:chomp(line));
        os += ' ' + version;
      }

      res["os"] = linux_kernel + " on " + os;
      res["confidence"] = default_confidence;
      res["type"] = "general-purpose";

      return res;
    }
    # No /etc/issue.net on Slackware 7.0 by default
    # No /etc/issue or issue.net on IcePack 2.75; no usable uname either
    #
    # TurboLinux release 6.0 English Server (Coyote)
    # Kernel 2.2.13-12smp on an i686 (.localdomain)
    # TTY: 0
    #
    # Red Flag Linux release 3.2
    # (same thing in /etc/redflag-release)
    #
    # $ more /etc/turbolinux-release
    # release 6.0 English Server (Coyote)
    # $ uname -a
    # Linux .localdomain 2.2.13-12smp #1 SMP Fri Dec 10 00:10:19 PST 1999 i686 unknown
    # $
    #
    # /etc/issue.net is empty on Slackware 12.1
  }
  else if ("MikroTik v" >< banner)
  {
    os = "MikroTik RouterOS";

    # MikroTik v3.2
    # Login:
    line = egrep(string: banner, pattern:"^MikroTik v[0-9][0-9.]+");
    if (line && line != banner)
    {
      version = ereg_replace(pattern:"^MikroTik v([0-9][0-9.]+).*", replace:"\1", string:line);
      os += ' v' + version;
    }

    res["os"] = os;
    res["confidence"] = default_confidence;
    res["type"] = "router";

    return res;
  }
  else if ("BCM96338 ADSL Router" >< banner)
  {
    res["os"] = "BCM96338 ADSL Router";
    res["confidence"] = 90;
    res["type"] = "router";

    return res;
  }
  else if ("Network Printer Server Version" >< banner)
  {
    res["os"] = "Printronix Printer";
    res["confidence"] = 95;
    res["type"] = "printer";

    return res;
  }
  # nb: http://en.wikipedia.org/wiki/Guardian_Service_Processor
  else if (egrep(pattern:"^Service Processor login:", string:banner))
  {
    res["os"] = "HP Guardian Service Processor";
    res["confidence"] = 90;
    res["type"] = "embedded";

    return res;
  }
  else if (
    "Hewlett-Packard Co." >< banner &&
    egrep(pattern:"ProCurve [^ ]+ Switch", string:banner)
  )
  {
    match = eregmatch(pattern:"ProCurve (J[0-9][0-9A-Z]+) Switch ([^ \r\n]+)", string:banner);
    if (isnull(match)) os = "HP Switch";
    else
    {
      os = "HP " + match[2] + " Switch (" + match[1] + ")";
      match = eregmatch(pattern:"Firmware revision ([A-Z][0-9A-Z.]+)", string:banner);
      if (!isnull(match)) os += " with software revision " + match[1];
    }

    res["os"] = os;
    res["confidence"] = 90;
    res["type"] = "switch";

    return res;
  }
  else if (
    "CP2E Control Console" >< banner ||
    (
      "Connected to Host: " >< banner &&
      egrep(pattern:"MPS-[^ ]+ Control Console", string:banner)
    )
  )
  {
    res["os"] = "Crestron Control Processor";
    res["confidence"] = 90;
    res["type"] = "embedded";

    return res;
  }
  else if (
    "Type HELP at the " >< banner &&
    "prompt for assistance." >< banner &&
    egrep(pattern:"Lantronix (MSS|UDS)", string:banner)
  )
  {
    res["os"] = 'Lantronix External Device Server';
    res["confidence"] = 95;
    res["type"] = "embedded";

    return res;
  }
  else if ("Promise VTrak Command Line Interface (CLI) Utility" >< banner)
  {
    res["os"] = 'Promise VTrak';
    res["confidence"] = 95;
    res["type"] = "embedded";

    return res;
  }
  else if ("VxWorks login:" >< banner)
  {
    res["os"] = 'VxWorks';
    res["confidence"] = 70;     # nb: keep low as VxWorks is used in a lot of embedded kit.
    res["type"] = "embedded";

    return res;
  }
  else if (
    "Copyright (c) Motorola, Inc." >< banner &&
    egrep(pattern:"AP-[^ ]+ Access Point [0-9]", string:banner)
  )
  {
    res["os"] = 'Motorola Wireless Access Point';
    res["confidence"] = 95;
    res["type"] = "wireless-access-point";

    return res;
  }
  else if (
    "IPSO (Nne)" >< banner &&
    "login:" >< banner
  )
  {
    res["os"] = "Nokia IPSO Firewall";
    res["confidence"] = 85;
    res["type"] = "firewall";

    return res;
  }
  else if (
    '\r\nTANDBERG Codec Release' >< banner &&
    '\r\nSW Release Date:' >< banner
  )
  {
    os = "Tandberg Video Conferencing";
    match = egrep(pattern:"^TANDBERG Codec Release .+", string:banner);
    if (match)
    {
      match = match - "TANDBERG ";
      os = strcat(os, " with ", chomp(match));
    }

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "embedded";

    return res;
  }
  else if (
    '\r\nThis session allows you to set the TCPIP parameters for your\r\nDell Laser Printer' >< banner &&
    'Network Firmware Version is' >< banner
  )
  {
    match = eregmatch(pattern:"Dell ([0-9]+)(cn?|cdn|cnw|dn?) ", string:banner);
    if (isnull(match)) os = "Dell Laser Printer";
    else
    {
      if (match[2] =~ "^c") os = strcat("Dell ", match[1], match[2], " Color Laser Printer");
      else os = strcat("Dell ", match[1], match[2], " Laser Printer");
    }

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "printer";

    return res;
  }
  else if (
    'Rugged Operating System v' >< banner &&
    'Copyright (c) RuggedCom, ' >< banner &&
    'Enter User Name:' >< banner
  )
  {
    os = "Rugged Operating System";

    match = eregmatch(pattern:"Rugged Operating System v([0-9\.]+) +\(", string:banner);
    if (!isnull(match)) os = os + " " + match[1];

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "embedded";

    return res;
  }
  else if (
    "Westermo EDW-" >< banner &&
    'login:' >< banner
  )
  {
    os = "Westermo EDW";

    match = eregmatch(pattern:"Westermo EDW-([0-9]+)", string:banner);
    if (!isnull(match)) os = os + "-" + match[1];

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "embedded";

    return res;
  }
  else if (
    "Fabric OS" >< banner &&
    egrep(pattern:"(Fabos Version |Release v)[0-9]", string:banner)
  )
  {
    os = "Brocade Switch";

    match = eregmatch(pattern:"(Fabos Version |Release v)([0-9]+\.[0-9a-z.]+)", string:banner);
    if (!isnull(match)) os += " with Fabric OS " + match[2];

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "switch";

    return res;
  }
  else if (
    "Nortel Networks" >< banner &&
    "* BayStack" >< banner
  )
  {
    os = "Nortel BayStack";

    match = eregmatch(pattern:"BayStack ([0-9][^ ]+)", string:banner);
    if (!isnull(match)) os += " " + match[1];
    os += " Switch";

    match = eregmatch(pattern:"SW:v([0-9][^ ]+)", string:banner);
    if (!isnull(match)) os += " with software release " + match[1];

    res["os"] = os;
    res["confidence"] = 60;
    res["type"] = "switch";

    return res;
  }
  else if (
    "Nortel Networks, Inc." >< banner &&
    "* Passport " >< banner
  )
  {
    os = "Nortel Passport";

    match = eregmatch(pattern:"Passport ([0-9][^ ]+)", string:banner);
    if (!isnull(match)) os += " " + match[1];
    os += " Switch";

    match = eregmatch(pattern:"Software Release ([0-9][^ ]+)", string:banner);
    if (!isnull(match)) os += " with software release " + match[1];

    res["os"] = os;
    res["confidence"] = 60;
    res["type"] = "switch";

    return res;
  }
  else if ("Nortel (Secure Router SR" >< banner)
  {
    os = "Nortel Secure Router";

    match = eregmatch(pattern:"Secure Router (SR[0-9][^ ]+)", string:banner);
    if (!isnull(match)) os += " " + match[1];

    match = eregmatch(pattern:"Version: ([0-9][^ ]+)", string:banner);
    if (!isnull(match)) os += " with software release " + match[1];

    res["os"] = os;
    res["confidence"] = 60;
    res["type"] = "router";

    return res;
  }
  else if ("NORTEL COMMAND LINE INTERFACE" >< banner)
  {
    os = "Nortel Switch";

    res["os"] = os;
    res["confidence"] = 60;
    res["type"] = "switch";

    return res;
  }
  else if (
    '\r\nLinux 2.2.14 (Nortel_WLan_2245)' >< banner &&
    '\r\nNortel_WLan_2245 login:' >< banner
  )
  {
    os = "Linux Kernel 2.2.14 on Nortel WLAN IP Telephony Manager 2245";

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "switch";

    return res;
  }
  else if (
    '\r\n\r\nUser Access Verification\r\n\r\nUsername: ' >< banner ||
    '\r\n\r\nUser Access Verification\r\n\r\nPassword: ' >< banner
  )
  {
    os = "Cisco";

    res["os"] = os;
    res["confidence"] = 66;
    res["type"] = "router";

    return res;
  }
  else if ('TServer Selesta telnet server' >< banner)
  {
    os = "Selesta ISOtech/g";

    res["os"] = os;
    res["confidence"] = 66;
    res["type"] = "embedded";

    return res;
  }
  else if ('\r\nNetDVRDVS:\n\nNetDVRDVS:\n' >< banner)
  {
    os = "Hikvision Digital Video Server";

    res["os"] = os;
    res["confidence"] = 71;
    res["type"] = "camera";

    return res;
  }
  else if ('FortiAuthenticator login:' >< banner)
  {
    # nb: not sure what OS this uses; it doesn't seem to be FortiOS.
    os = "Fortinet FortiAuthenticator";

    res["os"] = os;
    res["confidence"] = 75;
    res["type"] = "embedded";

    return res;
  }
  if (
    '*********Restricted Access*********' >< banner &&
    'Telnet password is not set' >< banner
  )
  {
    os = "ADTRAN Operating System";

    res["os"] = os;
    res["confidence"] = 75;
    res["type"] = "embedded";

    return res;
  }
  else if (
    'Select Access Level' >< banner &&
    '1 - Read-Only' >< banner &&
    '2 - Installer' >< banner &&
    '3 - Administrator' >< banner
  )
  {
    os = "Alvarion BreezeACCESS";

    res["os"] = os;
    res["confidence"] = 75;
    res["type"] = "wireless-access-point";

    return res;
  }
  else if (
    (
      'Meridian Integrated RAN Application' >< banner &&
      'Copyright (c) \x1b[1mNortel Networks.\x1b[m' >< banner &&
      '- Log On -' >< banner
    ) ||
    'Miran is *IN USE* via \x1b[1m' >< banner
  )
  {
    # nb: MIRAN provides multi-tasking voice processing applications
    #     such as recorded Announcement (RAN) and music-on-hold (MOH).
    os = "Nortel Meridian Integrated RAN (MIRAN)";

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "embedded";

    return res;
  }
  else if (
    "Check Point FireWall-1 Client Authentication Server" >< banner ||
    "Check Point FireWall-1 authenticated Telnet server" >< banner
  )
  {
    os = "Check Point GAiA";

    res["os"] = os;
    res["confidence"] = 75;
    res["type"] = "firewall";

    return res;
  }
  else if ('SX010203 login:' >< banner)
  {
    os = "Linux Kernel 2.6 on Silex SX-3000GB Gigabit USB Device Server";

    res["os"] = os;
    res["confidence"] = 71;
    res["type"] = "embedded";

    return res;
  }
  else if ("TiMOS-" >< banner && " ALCATEL " >< banner)
  {
    os = "TiMOS";
    match = eregmatch(pattern:"TiMOS-([^ ]+) .+ (ALCATEL.+?) Copyright", string:banner);
    if (!isnull(match)) os += " " + match[1] + ' on ' + match[2];

    res["os"] = os;
    res["confidence"] = 85;
    res["type"] = "router";

    return res;
  }
  else if (
    "IBM Networking Operating System RackSwitch" >< banner &&
    "Enter login username:" >< banner
  )
  {
    os = "IBM BNT";

    match = eregmatch(pattern:"IBM Networking Operating System RackSwitch ([A-Z][0-9]+)", string:banner);
    if (!isnull(match)) os += " " + match[1];

    res["os"] = os;
    res["confidence"] = 95;
    res["type"] = "switch";

    return res;
  }
  else if ('[ ConnectUPS Web/SNMP Card Configuration Utility ]' >< banner)
  {
    os = "ConnectUPS Web/SNMP Card";

    # nb: these devices are commonly but not exclusively
    #     associated with Eaton Powerware UPSes.
    match = eregmatch(pattern:"Firmware Revision V([0-9]+)", string:banner);
    if (!isnull(match)) os += " "+ match[1];

    res["os"] = os;
    res["confidence"] = 90;
    res["type"] = "embedded";

    return res;
  }
  else if (
    'HUAWEI SmartAX ' >< banner &&
    'series Multi-service Access Module' >< banner
  )
  {
    os = "Huawei SmartAX";

    match = eregmatch(pattern:"HUAWEI SmartAX ([^ ]+) series Multi-service Access Module", string:banner);
    if (!isnull(match)) os += " "+ match[1];

    res["os"] = os;
    res["confidence"] = 80;
    res["type"] = "embedded";  # 'dslam'?

    return res;
  }
  else if (
    '\r\nThere is another telnet server process active.\r\n\r\nWould you like to kill it (y/n) ? : \r' == banner ||
    (
      ' 4690 OS ' >< banner &&
      egrep(pattern:"Type.*your.+Operator.+ID", string:banner) &&
      egrep(pattern:"Copyright.+(IBM|Toshiba)", string:banner)
    )
  )
  {
    os = "Toshiba 4690 OS";

    match = eregmatch(pattern:"4690 OS[ \t]+Version[ \t]+([0-9]+[^ \t]*)", string:banner);
    if (!isnull(match)) os += " version "+ match[1];

    if ("another telnet server process" >< banner) conf = 70;
    else conf = 85;

    res["os"] = os;
    res["confidence"] = conf;
    res["type"] = "embedded";  # 'point-of-sale'?

    return res;
  }

  else if ('Welcome to Aerohive Wireless Product' >< banner)
  {
    os = "Aerohive HiveOS";

    res["os"] = os;
    res["confidence"] = 61;
    res["type"] = "embedded";

    return res;
  }

  else if (egrep(pattern:" SHARP (AR|MX)-.+ TELNET server", string:banner))
  {
    match = eregmatch(pattern:" SHARP ((AR|MX)-[^ ]+) Ver ([0-9][^ ]+) FTP server", string:banner);
    if (isnull(match))
    {
      os = "Sharp Printer";
      conf = 80;
    }
    else
    {
      os = "Sharp " + match[1] + " printer with firmware " + match[2];
      conf = 90;
    }

    res["os"] = os;
    res["confidence"] = conf;
    res["type"] = "printer";

    return res;
  }
  else if ('(xlweb)' >< banner)
  {
    os = "Honeywell XL Web Controller";

    res["os"] = os;
    res["confidence"] = 65;
    res["type"] = "embedded";

    return res;
  }
  else if ("D-Link Access Point" >< banner )
  {
    res["os"] = 'D-Link Wireless Access Point';
    res["confidence"] = 95;
    res["type"] = "wireless-access-point";

    return res;
  }
  else if (egrep(pattern:"/ ScreenOS [0-9.]+", string:banner) )
  {
    match = eregmatch(pattern:".* / ScreenOS ([0-9.a-z][^ ]+) .*", string:banner);
    res["os"] = 'ScreenOS ' + match[1];
    res["confidence"] = 95;
    res["type"] = "firewall";

    return res;
  }
  else if (egrep(pattern:"AXIS [0-9][^ ]+ TELNET Network Print Server", string:banner))
  {
    match = eregmatch(pattern:"AXIS ([0-9][^ ]+) TELNET Network Print Server( V([0-9][^ ]+))?", string:banner);
    if (isnull(match))
    {
      os = "AXIS Network Print Server";
      conf = 80;
    }
    else
    {
      os = "AXIS " + match[1] + " Network Print Server with firmware " + match[2];
      conf = 95;
    }

    res["os"] = os;
    res["confidence"] = conf;
    res["type"] = "printer";

    return res;
  }
  else if (egrep(pattern:"Meinberg LANTIME OS6 LOGIN", string:banner) )
  {
    res["os"] = 'Meinberg LANTIME OS6';
    res["confidence"] = 90;
    res["type"] = "scada";

    return res;
  }
  else if (
    'RTCS v' >< banner &&
    'Service Port Manager' >< banner &&
    '<Esc> Ends Session' >< banner
  )
  {
    res["os"] = 'Emerson Liebert IntelliSlot Web Card';
    res["confidence"] = 80;
    res["type"] = "embedded";

    return res;
  }
  else if (
    'ZebraNet' >< banner &&
    'PS' >< banner
  )
  {
    res["os"] = 'ZebraNet Printer Server';
    res["confidence"] = 80;
    res["type"] = "printer";

    return res;
  }
  # If we get here, there wasn't a match.
  return NULL;
}

kb_list = get_kb_list("Services/telnet");

if (isnull(kb_list)) ports = make_list();
else ports = make_list(kb_list);

foreach p (make_list(23))
{
  if (service_is_unknown(port:p))
  {
    ports = add_port_in_list(list:ports, port:p);
  }
}
if (max_index(ports) == 0) exit(0, "The host does not appear to have a listening Telnet server.");


highest_confidence = 0;
best_res = NULL;
foreach port (make_list(ports))
{
  res = check_banner(get_telnet_banner(port:port));
  if (!isnull(res))
  {
    if (res["confidence"] > highest_confidence)
    {
      highest_confidence = res["confidence"];
      best_res = res;
    }
  }
}

if (isnull(best_res)) exit(0, "Nessus was not able to identify the OS from a Telnet service banner.");

set_kb_item(name:"Host/OS/telnet", value:best_res["os"]);
set_kb_item(name:"Host/OS/telnet/Confidence", value:best_res["confidence"]);
set_kb_item(name:"Host/OS/telnet/Type", value:best_res["type"]);
