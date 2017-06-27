#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83186);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/24 13:12:23 $");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2014-6549",
    "CVE-2014-6585",
    "CVE-2014-6587",
    "CVE-2014-6591",
    "CVE-2014-6593",
    "CVE-2014-6601",
    "CVE-2015-0383",
    "CVE-2015-0395",
    "CVE-2015-0400",
    "CVE-2015-0403",
    "CVE-2015-0406",
    "CVE-2015-0407",
    "CVE-2015-0408",
    "CVE-2015-0410",
    "CVE-2015-0412",
    "CVE-2015-0413",
    "CVE-2015-0421",
    "CVE-2015-0437"
  );
  script_bugtraq_id(
    70574,
    72132,
    72136,
    72137,
    72140,
    72142,
    72146,
    72148,
    72150,
    72154,
    72155,
    72159,
    72162,
    72165,
    72168,
    72169,
    72173,
    72175,
    72176
  );
  script_osvdb_id(
    113251,
    117224,
    117225,
    117226,
    117227,
    117228,
    117229,
    117230,
    117231,
    117232,
    117233,
    117234,
    117235,
    117236,
    117237,
    117238,
    117239,
    117240,
    117241
  );
  script_xref(name:"CERT", value:"577193");
  script_xref(name:"VMSA", value:"2015-0003");

  script_name(english:"VMware vCenter Server Multiple Java Vulnerabilities (VMSA-2015-0003) (POODLE)");
  script_summary(english:"Checks the version of VMware vCenter.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a virtualization management application installed
that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The VMware vCenter Server installed on the remote host is version 5.0
prior to 5.0u3d, 5.1 prior to 5.1u3a, 5.5 prior to 5.5u2e, or 6.0 
prior to 6.0.0a. It is, therefore, affected by a man-in-the-middle
(MitM) information disclosure vulnerability known as POODLE, related
to the bundled JRE component. The vulnerability is due to the way SSL
3.0 handles padding bytes when decrypting messages encrypted using
block ciphers in cipher block chaining (CBC) mode. MitM attackers can
decrypt a selected byte of a cipher text in as few as 256 tries if
they are able to force a victim application to repeatedly send the
same data over newly created SSL 3.0 connections.

Additionally, multiple unspecified vulnerabilities also exist in the
following bundled JRE components :

  - 2D (CVE-2014-6585, CVE-2014-6591)

  - Deployment (CVE-2015-0403, CVE-2015-0406)

  - Hotspot (CVE-2014-6601, CVE-2015-0383, CVE-2015-0395,
    CVE-2015-0437)

  - Installation (CVE-2015-0421)

  - JAX-WS (CVE-2015-0412)

  - JSSE (CVE-2014-6593)

  - Libraries (CVE-2014-6549, CVE-2014-6587, CVE-2015-0400)

  - RMI (CVE-2015-0408)

  - Security (CVE-2015-0410)

  - Serviceability (CVE-2015-0413)

  - Swing (CVE-2015-0407)");
  script_set_attribute(attribute:"see_also", value:"http://www.vmware.com/security/advisories/VMSA-2015-0003.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2015/Apr/5");
  # http://www.oracle.com/technetwork/topics/security/cpujan2015-1972971.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c02f1515");
  # Java SE JDK and JRE 7 Update 75
  # http://www.oracle.com/technetwork/java/javase/7u75-relnotes-2389086.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?12e35b07");
  # Java SE JDK and JRE 6 Update 91
  # http://www.oracle.com/technetwork/java/javase/documentation/overview-156328.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?726f7054");
  script_set_attribute(attribute:"see_also", value:"https://www.imperialviolet.org/2014/10/14/poodle.html");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/~bodo/ssl-poodle.pdf");
  script_set_attribute(attribute:"see_also", value:"https://tools.ietf.org/html/draft-ietf-tls-downgrade-scsv-00");
  script_set_attribute(attribute:"solution", value:
"Upgrade to VMware vCenter Server 5.0u3d (5.0.0 build-2656067) / 5.1u3a
(5.1.0 build-2669725) / 5.5u2e (5.5.0 build-2646482) / 6.0.0a (6.0.0
build-2656757) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:vmware:vcenter_server");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("vmware_vcenter_detect.nbin");
  script_require_keys("Host/VMware/vCenter", "Host/VMware/version", "Host/VMware/release");
  script_require_ports("Services/www", 80, 443);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

port = get_kb_item_or_exit("Host/VMware/vCenter");
version = get_kb_item_or_exit("Host/VMware/version");
release = get_kb_item_or_exit("Host/VMware/release");

# Extract and verify the build number
build = ereg_replace(pattern:'^VMware vCenter Server [0-9\\.]+ build-([0-9]+)$', string:release, replace:"\1");
if (build !~ '^[0-9]+$') exit(1, 'Failed to extract the build number from the release string.');

release = release - 'VMware vCenter Server ';
fixversion = NULL;

# Check version and build numbers
if (version =~ '^VMware vCenter 5\\.0$' && int(build) < 2656067) fixversion = '5.0.0 build-2656067';
else if (version =~ '^VMware vCenter 5\\.1$' && int(build) < 2669725) fixversion = '5.1.0 build-2669725';
else if (version =~ '^VMware vCenter 5\\.5$' && int(build) < 2646482) fixversion = '5.5.0 build-2646482';
else if (version =~ '^VMware vCenter 6\\.0$' && int(build) < 2656757) fixversion = '6.0.0 build-2656757';
else audit(AUDIT_LISTEN_NOT_VULN, 'VMware vCenter', port, release);

if (report_verbosity > 0)
{
  report =
    '\n  Installed version : ' + release +
    '\n  Fixed version     : ' + fixversion +
    '\n';
  security_hole(port:port, extra:report);
}
else security_hole(port);
