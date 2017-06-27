#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(67217);
 script_version("$Revision: 1.21 $");
 script_cvs_date("$Date: 2017/01/24 21:49:30 $");

 script_name(english:"Cisco IOS XE Version");
 script_summary(english:"Obtains the version of the remote IOS XE.");

 script_set_attribute(attribute:"synopsis", value:
"Nessus was able to read the IOS XE version number of the remote Cisco
device.");
 script_set_attribute(attribute:"description", value:
"The remote host is running IOS XE, an operating system for Cisco
routers.

Nessus was able to read the IOS XE version number via an SSH
connection to the router or via SNMP.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/10");

 script_set_attribute(attribute:"plugin_type", value:"combined");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");

 script_dependencies("ssh_get_info.nasl", "snmp_sysDesc.nasl", "snmp_cisco_type.nasl", "cisco_default_pw.nasl");
 script_require_ports("Host/Cisco/show_ver", "SNMP/sysDesc");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

function remove_leading_zero(s)
{
  local_var str, temp, parts, part;
  parts = split(s, sep:".", keep:FALSE);
  foreach part (parts)
  {
    temp = ereg_replace(pattern:"^0(\d.*)", replace:"\1", string:part);
    if (temp == "") temp = "0";
    if (str) str = str + "." + temp;
    else str = temp;
  }
  return str;
}

function standardize_ver_format(ver)
{
  local_var matches;

  matches = eregmatch(string:ver, pattern:"([0-9]+)\.([0-9]+)\.([0-9]+)\.([a-zA-Z]+)");
  if (!isnull(matches)) return matches[1] + "." + matches[2] + "." + matches[3] + matches[4];

  matches = eregmatch(string:ver, pattern:"([0-9]+)\.([0-9]+)\.([0-9]+)([a-zA-Z]+)");
  if (!isnull(matches)) return ver;

  matches = eregmatch(string:ver, pattern:"([0-9]+)\.([0-9]+)\.([0-9]+)");
  if (!isnull(matches)) return ver;

  exit(1, "Failed to parse the version number of the remote host.");
}

function convert_ios_to_iosxe_ver(ver)
{
  if (ver == "12.2(33)XN")      ver = "2.0.0";
  if (ver == "12.2(33)XNA")     ver = "2.1.0";
  if (ver == "12.2(33)XNA1")    ver = "2.1.1";
  if (ver == "12.2(33)XNA2")    ver = "2.1.2";
  if (ver == "12.2(33)XNB")     ver = "2.2.0";
  if (ver == "12.2(33)XNB1")    ver = "2.2.1";
  if (ver == "12.2(33)XNB2")    ver = "2.2.2";
  if (ver == "12.2(33)XNB3")    ver = "2.2.3";
  if (ver == "12.2(33)XNC")     ver = "2.3.0";
  if (ver == "12.2(33)XNC0t")   ver = "2.3.0t";
  if (ver == "12.2(33)XNC1")    ver = "2.3.1";
  if (ver == "12.2(33)XNC1t")   ver = "2.3.1t";
  if (ver == "12.2(33)XNC2")    ver = "2.3.2";
  if (ver == "12.2(33)XND")     ver = "2.4.0";
  if (ver == "12.2(33)XND1")    ver = "2.4.1";
  if (ver == "12.2(33)XND2")    ver = "2.4.2";
  if (ver == "12.2(33)XND2t")   ver = "2.4.2t";
  if (ver == "12.2(33)XND3")    ver = "2.4.3";
  if (ver == "12.2(33)XND4")    ver = "2.4.4";
  if (ver == "12.2(33)XNE")     ver = "2.5.0";
  if (ver == "12.2(33)XNE1")    ver = "2.5.1";
  if (ver == "12.2(33)XNE2")    ver = "2.5.2";
  if (ver == "12.2(33)XNF")     ver = "2.6.0";
  if (ver == "12.2(33)XNF1")    ver = "2.6.1";
  if (ver == "12.2(33)XNF2")    ver = "2.6.2";
  if (ver == "15.0(1)EX")       ver = "3.2.0SE";
  if (ver == "15.0(1)EX1")      ver = "3.2.1SE";
  if (ver == "15.0(1)EX2")      ver = "3.2.2SE";
  if (ver == "15.0(1)EX3")      ver = "3.2.3SE";
  if (ver == "15.0(1)S")        ver = "3.1.0S";
  if (ver == "15.0(1)XO")       ver = "3.1.0SG";
  if (ver == "15.0(1)S1")       ver = "3.1.1S";
  if (ver == "15.0(1)XO1")      ver = "3.1.1SG";
  if (ver == "15.0(1)S2")       ver = "3.1.2S";
  if (ver == "15.0(1)S3")       ver = "3.1.3S";
  if (ver == "15.0(1)S4a")      ver = "3.1.4aS";
  if (ver == "15.0(1)S4")       ver = "3.1.4S";
  if (ver == "15.1(1)S")        ver = "3.2.0S";
  if (ver == "15.0(2)SG")       ver = "3.2.0SG";
  if (ver == "15.0(2)SG1")      ver = "3.2.1SG";
  if (ver == "15.0(2)SG10")     ver = "3.2.10SG";
  if (ver == "15.0(2)SG2")      ver = "3.2.2SG";
  if (ver == "15.0(2)SG3")      ver = "3.2.3SG";
  if (ver == "15.0(2)SG4")      ver = "3.2.4SG";
  if (ver == "15.0(2)SG5")      ver = "3.2.5SG";
  if (ver == "15.0(2)SG6")      ver = "3.2.6SG";
  if (ver == "15.0(2)SG7")      ver = "3.2.7SG";
  if (ver == "15.0(2)SG8")      ver = "3.2.8SG";
  if (ver == "15.0(2)SG9")      ver = "3.2.9SG";
  if (ver == "15.0(2)SQB")      ver = "3.3.0SQ";
  if (ver == "15.0(2)SQB1")     ver = "3.3.1SQ";
  if (ver == "15.0(2)SQC")      ver = "3.4.0SQ";
  if (ver == "15.0(2)SQC1")     ver = "3.4.1SQ";
  if (ver == "15.0(2)SQD")      ver = "3.5.0SQ";
  if (ver == "15.0(2)SQD1")     ver = "3.5.1SQ";
  if (ver == "15.0(2)SQD2")     ver = "3.5.2SQ";
  if (ver == "15.0(2)XO")       ver = "3.2.0XO";
  if (ver == "15.0(2)JA")       ver = "3.2.0JA";
  if (ver == "15.1(1)S1")       ver = "3.2.1S";
  if (ver == "15.1(1)S2")       ver = "3.2.2S";
  if (ver == "15.1(1)S3")       ver = "3.2.3S";
  if (ver == "15.1(2)S")        ver = "3.3.0S";
  if (ver == "15.0(1)EZ")       ver = "3.3.0SE";
  if (ver == "15.0(1)EZ1")      ver = "3.3.1SE";
  if (ver == "15.0(1)EZ2")      ver = "3.3.2SE";
  if (ver == "15.1(1)SG")       ver = "3.3.0SG";
  if (ver == "15.1(1)XO")       ver = "3.3.0XO";
  if (ver == "15.1(2)S1")       ver = "3.3.1S";
  if (ver == "15.1(1)SG1")      ver = "3.3.1SG";
  if (ver == "15.1(1)XO1")      ver = "3.3.1XO";
  if (ver == "15.1(2)S2")       ver = "3.3.2S";
  if (ver == "15.1(2)SG2")      ver = "3.3.2SG";
  if (ver == "15.1(2)XO2")      ver = "3.3.2XO";
  if (ver == "15.1(2)SE3")      ver = "3.3.3SE";
  if (ver == "15.1(2)SE4")      ver = "3.3.4SE";
  if (ver == "15.1(2)SE5")      ver = "3.3.5SE";
  if (ver == "15.1(3)S0a")      ver = "3.4.0aS";
  if (ver == "15.1(3)S")        ver = "3.4.0S";
  if (ver == "15.1(2)SG")       ver = "3.4.0SG";
  if (ver == "15.1(3)S1")       ver = "3.4.1S";
  if (ver == "15.1(3)SG1")      ver = "3.4.1SG";
  if (ver == "15.1(3)S2")       ver = "3.4.2S";
  if (ver == "15.1(3)SG2")      ver = "3.4.2SG";
  if (ver == "15.1(3)S3")       ver = "3.4.3S";
  if (ver == "15.1(3)SG3")      ver = "3.4.3SG";
  if (ver == "15.1(3)S4")       ver = "3.4.4S";
  if (ver == "15.1(3)SG4")      ver = "3.4.4SG";
  if (ver == "15.1(3)S5")       ver = "3.4.5S";
  if (ver == "15.1(3)SG5")      ver = "3.4.5SG";
  if (ver == "15.1(3)S6")       ver = "3.4.6S";
  if (ver == "15.1(3)SG6")      ver = "3.4.6SG";
  if (ver == "15.1(3)S7")       ver = "3.4.7S";
  if (ver == "15.1(3)SG7")      ver = "3.4.7SG";
  if (ver == "15.2(1)E")        ver = "3.5.0E";
  if (ver == "15.2(1)S")        ver = "3.5.0S";
  if (ver == "15.2(1)S1")       ver = "3.5.1S";
  if (ver == "15.2(1)E1")       ver = "3.5.1E";
  if (ver == "15.2(1)S2")       ver = "3.5.2S";
  if (ver == "15.2(1)E2")       ver = "3.5.2E";
  if (ver == "15.2(1)S3")       ver = "3.5.3S";
  if (ver == "15.2(1)E3")       ver = "3.5.3E";
  if (ver == "15.2(2)E")        ver = "3.6.0E";
  if (ver == "15.2(2)S")        ver = "3.6.0S";
  if (ver == "15.2(2)S1")       ver = "3.6.1S";
  if (ver == "15.2(2)E1")       ver = "3.6.1E";
  if (ver == "15.2(2)S2")       ver = "3.6.2S";
  if (ver == "15.2(2)E2")       ver = "3.6.2E";
  if (ver == "15.2(2)E2a")      ver = "3.6.2aE";
  if (ver == "15.2(2)E3")       ver = "3.6.3E";
  if (ver == "15.2(2)E4")       ver = "3.6.4E";
  if (ver == "15.2(3)E")        ver = "3.7.0E";
  if (ver == "15.2(4)S")        ver = "3.7.0S";
  if (ver == "15.2(4)S0b")      ver = "3.7.0bS";
  if (ver == "15.2(4)S1")       ver = "3.7.1S";
  if (ver == "15.2(4)S1a")      ver = "3.7.1aS";
  if (ver == "15.2(4)E1")       ver = "3.7.1E";
  if (ver == "15.2(4)S2")       ver = "3.7.2S";
  if (ver == "15.2(4)S2t")      ver = "3.7.2tS";
  if (ver == "15.2(4)E2")       ver = "3.7.2E";
  if (ver == "15.2(4)S3")       ver = "3.7.3S";
  if (ver == "15.2(4)E3")       ver = "3.7.3E";
  if (ver == "15.2(4)S4")       ver = "3.7.4S";
  if (ver == "15.2(4)S4a")      ver = "3.7.4aS";
  if (ver == "15.2(4)S5")       ver = "3.7.5S";
  if (ver == "15.2(4)S6")       ver = "3.7.6S";
  if (ver == "15.2(4)S7")       ver = "3.7.7S";
  if (ver == "15.3(1)S")        ver = "3.8.0S";
  if (ver == "15.3(1)S1")       ver = "3.8.1S";
  if (ver == "15.3(1)E")        ver = "3.8.0E";
  if (ver == "15.3(1)E1")       ver = "3.8.1E";
  if (ver == "15.3(1)S2")       ver = "3.8.2S";
  if (ver == "15.3(2)S")        ver = "3.9.0S";
  if (ver == "15.3(2)S0a")      ver = "3.9.0aS";
  if (ver == "15.3(2)S1")       ver = "3.9.1S";
  if (ver == "15.3(2)S1a")      ver = "3.9.1aS";
  if (ver == "15.3(2)S2")       ver = "3.9.2S";
  if (ver == "15.3(3)S")        ver = "3.10.0S";
  if (ver == "15.3(3)S0a")      ver = "3.10.0aS";
  if (ver == "15.3(3)S1")       ver = "3.10.1S";
  if (ver == "15.3(3)S1xb")     ver = "3.10.1xbS";
  if (ver == "15.3(3)S2")       ver = "3.10.2S";
  if (ver == "15.3(3)S2t")      ver = "3.10.2tS";
  if (ver == "15.3(3)S3")       ver = "3.10.3S";
  if (ver == "15.3(3)S4")       ver = "3.10.4S";
  if (ver == "15.3(3)S5")       ver = "3.10.5S";
  if (ver == "15.3(3)S6")       ver = "3.10.6S";
  if (ver == "15.3(3)S7")       ver = "3.10.7S";
  if (ver == "15.3(4)S")        ver = "3.11.0S";
  if (ver == "15.3(4)S1")       ver = "3.11.1S";
  if (ver == "15.3(4)S2")       ver = "3.11.2S";
  if (ver == "15.3(4)S3")       ver = "3.11.3S";
  if (ver == "15.3(4)S4")       ver = "3.11.4S";
  if (ver == "15.4(2)S")        ver = "3.12.0S";
  if (ver == "15.4(2)S0a")      ver = "3.12.0aS";
  if (ver == "15.4(2)S1")       ver = "3.12.1S";
  if (ver == "15.4(2)S2")       ver = "3.12.2S";
  if (ver == "15.4(2)S3")       ver = "3.12.3S";
  if (ver == "15.4(2)S4")       ver = "3.12.4S";
  if (ver == "15.4(3)S")        ver = "3.13.0S";
  if (ver == "15.4(3)Sa")       ver = "3.13.0aS";
  if (ver == "15.4(3)S1")       ver = "3.13.1S";
  if (ver == "15.4(3)S2")       ver = "3.13.2S";
  if (ver == "15.4(3)S2a")      ver = "3.13.2aS";
  if (ver == "15.4(3)S3")       ver = "3.13.3S";
  if (ver == "15.4(3)S4")       ver = "3.13.4S";
  if (ver == "15.4(3)S5")       ver = "3.13.5S";
  if (ver == "15.5(1)S")        ver = "3.14.0S";
  if (ver == "15.5(1)S1")       ver = "3.14.1S";
  if (ver == "15.5(1)S2")       ver = "3.14.2S";
  if (ver == "15.5(1)S3")       ver = "3.14.3S";
  if (ver == "15.5(1)S4")       ver = "3.14.4S";
  if (ver == "15.5(2)S0.1")     ver = "3.15.0.1S";
  if (ver == "15.5(2)S")        ver = "3.15.0S";
  if (ver == "15.5(2)S1")       ver = "3.15.1S";
  if (ver == "15.5(2)S1c")      ver = "3.15.1cS";
  if (ver == "15.5(2)S2")       ver = "3.15.2S";
  if (ver == "15.5(2)S3")       ver = "3.15.3S";
  if (ver == "15.5(3)S")        ver = "3.16.0S";
  if (ver == "15.5(3)Sc")       ver = "3.16.0cS";
  if (ver == "15.5(3)S1")       ver = "3.16.1S";
  if (ver == "15.5(3)S1a")      ver = "3.16.1aS";
  if (ver == "15.5(3)S2")       ver = "3.16.2S";
  if (ver == "15.5(3)S2a")      ver = "3.16.2aS";
  if (ver == "15.5(3)S3")       ver = "3.16.3S";
  if (ver == "15.6(1)S")        ver = "3.17.0S";
  if (ver == "15.6(1)S1")       ver = "3.17.1S";
  if (ver == "15.6(2)S")        ver = "3.18.0S";

  return ver;
}

function test(s, ssh)
{
  local_var v, l, ver, image;
  local_var os, type, source;
  local_var report, model, banner_pieces, matches;
  local_var l2, l2_pattern, m2, model_line;

  if (empty_or_null(s)) return;

  # snmp match
  # ssh match
  # Cisco IOS Software, IOS-XE Software, Catalyst 4500 L3 Switch Software (cat4500e-UNIVERSALK9-M), Version 03.03.00.SG RELEASE SOFTWARE (fc3)
  # Cisco IOS Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version Denali 16.2.1, RELEASE SOFTWARE (fc1)
  l = egrep(string:s, pattern:"^.* IOS[ -]XE Software.*, Version [0-9][0-9.a-zA-Z\(\)]+,?");
  if (empty_or_null(l))
    l = egrep(string:s, pattern:"^.*IOS.*Version (Denali|Everest) [0-9.]+.*");

  if (l != "")
    v = eregmatch(string:l, pattern:", Version +((Denali|Everest)? ?([0-9]+\.[0-9]+[^ ,]+))");

  if (empty_or_null(v[1])) return;

  ver = chomp(v[3]);
  if(isnull(v[2]))
  {
    # attempt to convert any IOS versions to IOS-XE versions
    ver = convert_ios_to_iosxe_ver(ver:ver);

    # fix ver...   remove leading 0's
    ver = remove_leading_zero(s:ver);

    # clean up the version by standardizing on a version format
    ver = standardize_ver_format(ver:ver);
  }

  set_kb_item(name:"Host/Cisco/IOS-XE/Version", value: ver);

  # Extract model if possible
  # Model is present example :
  # Cisco IOS Software, IOS-XE Software, Catalyst L3 Switch Software (CAT3K_CAA-UNIVERSALK9-M), Version 03.03.01SE RELEASE SOFTWARE (fc1)
  # Model is NOT present example :
  # Cisco IOS Software, IOS-XE Software (X86_64_LINUX_IOSD-UNIVERSAL-M), Version 15.2(4)S, RELEASE SOFTWARE (fc4)
  banner_pieces = split(l, sep:", ", keep:FALSE);

  # Use second line if not enough info
  if (isnull(banner_pieces[2]))
  {
    model_line = egrep(string:s, pattern:"IOS Software,.*Software.*Version [0-9][0-9.a-zA-Z]+.*");
    if (model_line != "")
      banner_pieces = split(model_line, sep:", ", keep:FALSE);
  }

  if (
    !isnull(banner_pieces[2]) &&
    (
      "Cisco IOS Software" >< banner_pieces[0] || # Allow CSR1000V and like to pass
      "IOS-XE Software" >< banner_pieces[1] ||
      "IOS XE Software" >< banner_pieces[1]
    )
  )
  {
    matches = eregmatch(string:banner_pieces[2], pattern:"^(.*) Software \(.*$");
    if (!empty_or_null(matches[1]))
    {
      set_kb_item(name:"Host/Cisco/IOS-XE/Model", value: matches[1]);
      model = matches[1];
    }
    else
    {
      # We're looking at IOS-XE, but model may be on the second line.
      # IOS-XE virtual appliance is an example; see the two lines :
      # Cisco IOS XE Software, Version 03.10.00.S - Extended Support Release
      # Cisco IOS Software, CSR1000V Software (X86_64_LINUX_IOSD-UNIVERSALK9-M), Version 15.3(3)S, RELEASE SOFTWARE (fc1)
      l2_pattern = "Cisco IOS Software, (.*) Software \([^)]+\), Version.*";
      l2 = egrep(string:s, pattern:l2_pattern);
      if (l2 != "")
        m2 = eregmatch(string:l2, pattern:l2_pattern);

      if (!empty_or_null(m2[1]) && "IOS-XE" != m2[1] && "IOS XE" != m2[1])
      {
        set_kb_item(name:"Host/Cisco/IOS-XE/Model", value: m2[1]);
        model = m2[1];
      }
    }
  }

  image = eregmatch(string: l, pattern: "\((.*)\), *Version");
  if (!empty_or_null(image[1]))
  {
    image = image[1];
    set_kb_item(name:"Host/Cisco/IOS-XE/Image", value: image);
  }

  type = "router";

  source = "SNMP";

  if (ssh == TRUE)
  {
   source = "SSH";
   os = "Cisco IOS XE " + ver;
   set_kb_item(name:"Host/OS/CiscoShell", value:os);
   set_kb_item(name:"Host/OS/CiscoShell/Confidence", value:100);
   set_kb_item(name:"Host/OS/CiscoShell/Type", value:type);
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  Source  : ' + source +
      '\n  Version : ' + ver;

    if (!isnull(model))
      report += '\n  Model   : ' + model;

    report += '\n';
    security_note(port:0, extra:report);
  }
  else security_note(0);

  exit(0);
}

# 1. SSH
showver = get_kb_item("Host/Cisco/show_ver");
test(s: showver, ssh:1);

# 2. SNMP
desc = get_kb_item("SNMP/sysDesc");
test(s: desc);

exit(0, 'The Cisco IOS-XE version is not available (the remote host may not be Cisco IOS-XE).');
