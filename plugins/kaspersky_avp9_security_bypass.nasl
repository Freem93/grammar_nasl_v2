#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(40446);
  script_version("$Revision: 1.7 $");

  script_cve_id("CVE-2009-2647");
  script_bugtraq_id(35789);
  script_osvdb_id(56351);
  script_xref(name:"Secunia", value:"35978");

  script_name(english:"Kaspersky Internet Security / Anti-Virus External Script Unspecified Protection Mechanism Bypass");
  script_summary(english:"Checks product version");
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an antivirus application that is
affected by a security bypass vulnerability." );

  script_set_attribute(attribute:"description", value:
"The version of the Kaspersky antivirus product installed on the
remote host is affected by a security bypass vulnerability.  By using
a specially crafted external script, an attacker may be able to
disable the computer protection provided by the antivirus software.");

   # http://web.archive.org/web/20100112103007/http://www.kaspersky.com/technews?id=203038755
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?f891a116" );

  script_set_attribute(attribute:"solution", value:
"Upgrade if necessary to Kaspersky Anti-Virus / Kaspersky Internet
Security 2010, and then to build 9.0.0.463 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 
  script_set_attribute(attribute:"vuln_publication_date",   value:"2009/07/23");
  script_set_attribute(attribute:"patch_publication_date",  value:"2009/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/31");

 script_cvs_date("$Date: 2016/05/11 13:32:18 $");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:kaspersky_lab:kaspersky_anti-virus");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("kaspersky_installed.nasl");
  script_require_keys("Antivirus/Kaspersky/installed");

  exit(0);
}

include("global_settings.inc");

if (!get_kb_item("Antivirus/Kaspersky/installed")) exit(1, "'Antivirus/Kaspersky/installed' KB item is missing.");

port = get_kb_item("SMB/transport");

prods = make_list(
  "Kaspersky Anti-Virus", 
  "Kaspersky Internet Security"
);

info = '';
foreach prod (prods)
{
  install = get_kb_item("Antivirus/Kaspersky/" + prod);
  if (!isnull(install))
  {
    matches = eregmatch(pattern:"^([0-9.]+) in (.*)$", string:install);
 
    if (!isnull(matches))
    {
      ver = matches[1];
      iver = split(ver, sep:'.', keep:FALSE);
      for (i=0; i<max_index(iver); i++)
        iver[i] = int(iver[i]);

      # nb: Kaspersky Anti-Virus / Kaspersky Internet Security 2010 == AVP 9.0
      if (
        iver[0] < 9 ||
        (iver[0] == 9 && iver[1] == 0 && iver[2] == 0 && iver[3] < 463)
      ) info += '  - ' + prod + ' version ' + ver + '\n';
    }
  }
}

if(info)
{
  if(report_verbosity > 0)
  {
   report = string(
        "\n",      
        "Nessus found the following vulnerable Kaspersky product(s)\n",
        "installed :\n",
        "\n",
        info);
   security_warning(port:port, extra:report);
  } 
  else security_warning(port);
  exit(0);
}
else exit(0, "No vulnerable instance of Kaspersky Anti-Virus / Internet Security was found.");
