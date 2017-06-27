#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53471);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/12/18 01:33:18 $");

  script_name(english:"OS Identification : HNAP");
  script_summary(english:"Identifies devices based on info collected via HNAP");

  script_set_attribute(
    attribute:"synopsis",
    value:
"It is possible to identify the remote operating system based on
information collected via HNAP."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote operating system can be identified through information
collected via HNAP (Home Network Administration Protocol)."
  );
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/18");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"General");

  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");

  script_dependencie("hnap_detect.nasl");
  script_require_keys("www/hnap");
  script_require_ports("Services/www");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded:TRUE);


# Extract some info from the HNAP service.
get_kb_item_or_exit("www/"+port+"/hnap");

res = http_get_cache(item:"/HNAP1/", port:port, exit_on_fail:TRUE);

fingerprint = "";
vendor = "";
if ("<VendorName>" >< res && "</VendorName>" >< res)
{
   vendor = strstr(res, "<VendorName>") - "<VendorName>";
   vendor = vendor- strstr(vendor, "</VendorName>");
   fingerprint += 'vendor=' + vendor + '; ';
}

model = "";
if ("<ModelName>" >< res && "</ModelName>" >< res)
{
   model = strstr(res, "<ModelName>") - "<ModelName>";
   model = model - strstr(model, "</ModelName>");
   fingerprint += 'model=' + model + '; ';
}

if (strlen(fingerprint) > 0)
{
  fingerprint = substr(fingerprint, 0, strlen(fingerprint)-3);
  set_kb_item(name:"Host/OS/HNAP/Fingerprint", value:fingerprint);
}
else exit(0, "Failed to extract vendor / model information from the HNAP service on port "+port+".");


# Define our signatures.
i = 0;
name          = make_array();           # nb: '$1' in the name is replaced by a match, if any, from the model pattern
confidence    = make_array();
dev_type      = make_array();
model_pat     = make_array();
vendor_pat    = make_array();

name[i]       = "D-Link Wireless Access Point - $1";
dev_type[i]   = "wireless-access-point";
model_pat[i]  = "^(DIR-6[1245]5(.+)?|DSL-2890AL)";
vendor_pat[i] = "^D-Link";
i++;

name[i]       = "Linksys Wireless Access Point - $1";
dev_type[i]   = "wireless-access-point";
model_pat[i]  = "^((E|EA|WET)[0-9][^ ]+)";
vendor_pat[i] = "^Linksys( by Cisco|$)";
i++;

name[i]       = "Linksys Router - $1";
dev_type[i]   = "router";
model_pat[i]  = "^(WRT[0-9][^ ]+)";
vendor_pat[i] = "^Linksys";
i++;

name[i]       = "Netgear Wireless Router ($1)";
dev_type[i]   = "wireless-access-point";
model_pat[i]  = "^(WNR[0-9]+)";
vendor_pat[i] = "^Netgear";
i++;

# Finally, loop through each signature looking for a match.
default_confidence = 95;
default_type = 'embedded';

n = i;
for (i=0; i<n; i++)
{
  if (
    (
      !vendor_pat[i] ||
      (vendor && eregmatch(pattern:vendor_pat[i], string:vendor))
    ) &&
    (
      !model_pat[i] ||
      (model && eregmatch(pattern:model_pat[i], string:model))
    )
  )
  {
    name = name[i];
    if ("$1" >< name && model && model_pat[i])
    {
      model_match = eregmatch(pattern:model_pat[i], string:model);
      if (!isnull(model_match) && model_match[1])
        name = str_replace(find:"$1", replace:model_match[1], string:name);
    }

    if (confidence[i]) conf = confidence[i];
    else conf = default_confidence;

    if (dev_type[i]) type = dev_type[i];
    else type = default_type;

    set_kb_item(name:"Host/OS/HNAP", value:name);
    set_kb_item(name:"Host/OS/HNAP/Confidence", value:conf);
    set_kb_item(name:"Host/OS/HNAP/Type", value:type);
    exit(0);
  }
}
exit(0, "Nessus was not able to identify the OS from the HNAP service listening on port "+port+".");
