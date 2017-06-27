#TRUSTED 6e4c22b06f8e47ad9ae958c0d040221c72d64ca6b43a8e3b6663138646718f9fa2ef9f0389646bc7b36fa7a3f88e44f3d1fd48e10fc40d49a02d8b6753be8fc1dde9463ccdf7b93c7493e2ffebaf835cf8f8a6cb08799d83a5f9f5896f0511f83589a478624c0ef20b2867d6efe76f18f5a863419643e73c95e17d92c9ab3ba5b3b124f5dde9a670b05e5a5b358a36926edb9ce02966c75b4ada54fe5eed46d4541aaf90b14b806b025c063e4df6beb7f1e3b147a48262ebf3143399752a13d6dc867ab2fc7feaf502b3aaa25f97ab29c297cc20ee7b7add7f349f6625409db81361ec804af75eda11db31c963a866a1fc7ee9cfa2cf568371c8bd1991fba2bd885a763b321a85e568c3f3c213591a7f3eddf8a70f3bac7117e42fe178d5295e4aad1cec9f9eb932fe4a483265a8f3a7ffb19aab5eed889dbf00effcb1403129d305143309351447d9095a5406fdc98f8e1059ee4da5a3af103293e88157aca5e543917ad57ef5d939f620c3fe291c1b452ac6f9f64bdea7273addf3998a53d71c12904800f29889121d5aff54e4f49b17a316e7f2b8320cd57e3cfb36eb81627998afa2be85e172b5b3ddaa689aad1f5863979f00893c1b023c901c75fbd14efb3e101278d0e27c8f2e90d1655a32dd455ec4ee9702b4ab68622831ac79ae98ef59afd8a2aa4ae6327534e9fd9aab39b9f28b439ffb802efe14bb35e9ba9ab7
#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77756);
  script_version("1.5");
  script_set_attribute(attribute:"plugin_modification_date", value:"2017/05/16");

  script_cve_id("CVE-2013-5211");
  script_bugtraq_id(64692);
  script_osvdb_id(101576);
  script_xref(name:"CERT", value:"348126");
  script_xref(name:"EDB-ID", value:"33073");
  script_xref(name:"ICSA", value:"14-051-04");
  script_xref(name:"JSA", value:"JSA10613");

  script_name(english:"Juniper Junos NTP Server Amplification Remote DoS (JSA10613)");
  script_summary(english:"Checks the Junos version, build date, and configuration.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the remote Juniper
Junos device is affected by a vulnerability in the NTP daemon related
to the handling of the 'monlist' command. A remote attacker can
exploit this by forging a request that results in a distributed denial
of service.

Note that this issue only affects devices with NTP client or server
enabled.");
  script_set_attribute(attribute:"see_also", value:"https://kb.juniper.net/InfoCenter/index?page=content&id=JSA10613");
  script_set_attribute(attribute:"solution", value:
"Apply the relevant Junos software release or workaround referenced in
Juniper advisory JSA10613.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:juniper:junos");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ntp:ntp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Junos Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

  script_dependencies("junos_version.nasl");
  script_require_keys("Host/Juniper/JUNOS/Version", "Host/Juniper/JUNOS/BuildDate");

  exit(0);
}

include("audit.inc");
include("junos_kb_cmd_func.inc");
include("misc_func.inc");

ver = get_kb_item_or_exit('Host/Juniper/JUNOS/Version');
build_date = get_kb_item_or_exit('Host/Juniper/JUNOS/BuildDate');

# Junos OS 14.1R1 release date
if (compare_build_dates(build_date, '2014-06-07') >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'Junos', ver + ' (build date ' + build_date + ')');

fixes = make_array();
fixes['11.4']    = '11.4R12';
fixes['12.1']    = '12.1R10';
fixes['12.1X44'] = '12.1X44-D35';
fixes['12.1X45'] = '12.1X45-D25';
fixes['12.1X46'] = '12.1X46-D15';
fixes['12.1X47'] = '12.1X47-D10';
fixes['12.2']    = '12.2R8';
fixes['12.3']    = '12.3R7';
fixes['13.1']    = '13.1R4-S2';
fixes['13.2']    = '13.2R4';
fixes['13.3']    = '13.3R2';
fixes['14.1']    = '14.1R1';

fix = check_junos(ver:ver, fixes:fixes, exit_on_fail:TRUE);

# Check for NTP
override = TRUE;
buf = junos_command_kb_item(cmd:"show configuration | display set");
if (buf)
{
  pattern = "^set system ntp server";
  if (!junos_check_config(buf:buf, pattern:pattern))
    audit(AUDIT_HOST_NOT, 'affected because neither a NTP client nor server are enabled');
  override = FALSE;
}

junos_report(ver:ver, fix:fix, override:override, severity:SECURITY_WARNING);
