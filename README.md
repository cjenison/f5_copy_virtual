#H1 f5_copy_virtual

#H2 Overview: This script's intent is to copy a virtual server and all referenced dependencies (e.g. pools, iRules, profiles) to a destination.

#H3 It uses iControl REST (available in BIG-IP 11.5.x+) to accomplish this and leverages the JSON data format used by iControl as a representation of the BIG-IP configuration.

It has three modes of operation:
- get: Retrieve configuration from one or more virtual servers and output a file with the virtual servers and all dependencies
- put: Read input produced by an invocation of the tool using the -get option; apply the configuration to a destination BIG-IP
- copy: In one pass, without writing a file, retrieve configuration from source and then apply to destination

In general, the code tries to handle this as generically as possible.

The output file format is as follows:
{
 Top-level items/keys are meta-data about the source BIG-IP (e.g. MAC address, hostname, software revisions, provisioning
 virtuals: [array of {virtua]} items]
   {virtual}: { virtualFullPath: "sourceFullPath for virtual server", virtualListConfig: [{JSON BLOB1},{JSON BLOB2}] 
}

Note that the JSON BLOBs in each virtualListConfig have the following characteristics:
- They appear in the order in which they should be applied on a destination BIG-IP so that POST'ing any Blob doesn't result in missing depedencies.
- Consequently the Virtual Server JSON Blob is the last item in each virtualListConfig
- With only a few exceptions (primarily configuration objects that have a file associated with them) the data in the file is unmodified from the "GET" that was issued to the source machine.
- For SSL Key and Cert files, an additional item 'text' has been inserted by the code to include the text version of the key or cert
