package ca.ubc.cs.cs317.dnslookup;

import java.io.*;
import java.net.*;
import java.nio.ByteBuffer;
import java.util.*;

public class DNSLookupService {

    private static final int DEFAULT_DNS_PORT = 53;
    private static final int MAX_INDIRECTION_LEVEL = 10;

    private static InetAddress rootServer;
    private static boolean verboseTracing = false;
    private static DatagramSocket socket;
    private static DNSNode dnsAnswer;
    private static DNSCache cache = DNSCache.getInstance();
    private static Random random = new Random();

    private static RecordType DNSType;
    private static byte[] dnsFrame;
    private static boolean root = true;
    private static int authBit = 0;
    private static boolean resentBit = false;
    private static int queryID = 0;
    private static boolean isIP = false;


    /**
     * Main function, called when program is first invoked.
     *
     * @param args list of arguments specified in the command line.
     */
    public static void main(String[] args) {

        if (args.length != 1) {
            System.err.println("Invalid call. Usage:");
            System.err.println("\tjava -jar DNSLookupService.jar rootServer");
            System.err.println("where rootServer is the IP address (in dotted form) of the root DNS server to start the search at.");
            System.exit(1);
        }

        try {
            rootServer = InetAddress.getByName(args[0]);
            System.out.println("Root DNS server is: " + rootServer.getHostAddress());
        } catch (UnknownHostException e) {
            System.err.println("Invalid root server (" + e.getMessage() + ").");
            System.exit(1);
        }

        try {
            socket = new DatagramSocket();
            socket.setSoTimeout(5000);
        } catch (SocketException ex) {
            ex.printStackTrace();
            System.exit(1);
        }

        Scanner in = new Scanner(System.in);
        Console console = System.console();
        do {
            // Use console if one is available, or standard input if not.
            String commandLine;
            if (console != null) {
                System.out.print("DNSLOOKUP> ");
                commandLine = console.readLine();
            } else
                try {
                    System.out.print("DNSLOOKUP> ");
                    commandLine = in.nextLine();
                } catch (NoSuchElementException ex) {
                    break;
                }
            // If reached end-of-file, leave
            if (commandLine == null) break;

            // Ignore leading/trailing spaces and anything beyond a comment character
            commandLine = commandLine.trim().split("#", 2)[0];

            // If no command shown, skip to next command
            if (commandLine.trim().isEmpty()) continue;

            String[] commandArgs = commandLine.split(" ");

            if (commandArgs[0].equalsIgnoreCase("quit") ||
                    commandArgs[0].equalsIgnoreCase("exit"))
                break;
            else if (commandArgs[0].equalsIgnoreCase("server")) {
                // SERVER: Change root nameserver
                if (commandArgs.length == 2) {
                    try {
                        rootServer = InetAddress.getByName(commandArgs[1]);
                        System.out.println("Root DNS server is now: " + rootServer.getHostAddress());
                    } catch (UnknownHostException e) {
                        System.out.println("Invalid root server (" + e.getMessage() + ").");
                        continue;
                    }
                } else {
                    System.out.println("Invalid call. Format:\n\tserver IP");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("trace")) {
                // TRACE: Turn trace setting on or off
                if (commandArgs.length == 2) {
                    if (commandArgs[1].equalsIgnoreCase("on"))
                        verboseTracing = true;
                    else if (commandArgs[1].equalsIgnoreCase("off"))
                        verboseTracing = false;
                    else {
                        System.err.println("Invalid call. Format:\n\ttrace on|off");
                        continue;
                    }
                    System.out.println("Verbose tracing is now: " + (verboseTracing ? "ON" : "OFF"));
                } else {
                    System.err.println("Invalid call. Format:\n\ttrace on|off");
                    continue;
                }
            } else if (commandArgs[0].equalsIgnoreCase("lookup") ||
                    commandArgs[0].equalsIgnoreCase("l")) {
                // LOOKUP: Find and print all results associated to a name.
                RecordType type;
                if (commandArgs.length == 2) {
                    type = RecordType.A;
                }
                else if (commandArgs.length == 3)
                    try {
                        type = RecordType.valueOf(commandArgs[2].toUpperCase());
                    } catch (IllegalArgumentException ex) {
                        System.err.println("Invalid query type. Must be one of:\n\tA, AAAA, NS, MX, CNAME");
                        continue;
                    }
                else {
                    System.err.println("Invalid call. Format:\n\tlookup hostName [type]");
                    continue;
                }
                DNSType = type;
                resentBit = false;
                findAndPrintResults(commandArgs[1], type);
            } else if (commandArgs[0].equalsIgnoreCase("dump")) {
                // DUMP: Print all results still cached
                cache.forEachNode(DNSLookupService::printResults);
            } else {
                System.err.println("Invalid command. Valid commands are:");
                System.err.println("\tlookup fqdn [type]");
                System.err.println("\ttrace on|off");
                System.err.println("\tserver IP");
                System.err.println("\tdump");
                System.err.println("\tquit");
                continue;
            }

        } while (true);

        socket.close();
        System.out.println("Goodbye!");
    }

    /**
     * Finds all results for a host name and type and prints them on the standard output.
     *
     * @param hostName Fully qualified domain name of the host being searched.
     * @param type     Record type for search.
     */
    private static void findAndPrintResults(String hostName, RecordType type) {

        DNSNode node = new DNSNode(hostName, type);
        printResults(node, getResults(node, 0));
    }

    /**
     * Finds all the result for a specific node.
     *
     * @param node             Host and record type to be used for search.
     * @param indirectionLevel Control to limit the number of recursive calls due to CNAME redirection.
     *                         The initial call should be made with 0 (zero), while recursive calls for
     *                         regarding CNAME results should increment this value by 1. Once this value
     *                         reaches MAX_INDIRECTION_LEVEL, the function prints an error message and
     *                         returns an empty set.
     * @return A set of resource records corresponding to the specific query requested.
     */
    private static Set<ResourceRecord> getResults(DNSNode node, int indirectionLevel) {

        if (indirectionLevel > MAX_INDIRECTION_LEVEL) {
            System.err.println("Maximum number of indirection levels reached.");
            return Collections.emptySet();
        }
        try {
            resetGlobalVariables();
            dnsFrame = createOutputMessage(node);
            InetAddress ia = InetAddress.getByName(node.getHostName());
            retrieveResultsFromServer(node, ia);
            if (!isIP) {
                indirectionLevel++;
                return getResults(dnsAnswer, indirectionLevel);

            }

        } catch (IOException e) {
            if (resentBit) {
                return Collections.emptySet();
            } else {
                resentBit = true;
                return getResults(node, indirectionLevel);
            }
        }
        return cache.getCachedResults(dnsAnswer);
    }


    /**
     * Resets all of the global variables that are used throughout the program when necessary.
     * Called only in the above function getResults.
     *
     */
    private static void resetGlobalVariables() {
        root = true;
        authBit = 0;
        isIP = false;
    }


    /**
     * Creates what is going to be sent out
     *
     * @param node             is used for retrieving/setting the domain name
     *
     * @return A byte array corresponding to our desired output message, can changed based on which
     *         stage of the output we want.
     */
    private static byte[] createOutputMessage(DNSNode node) throws IOException {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);
        if (resentBit) {
            dos.writeShort(queryID);
        } else {
            queryID = getQueryId();
            dos.writeShort(queryID);
        }
        //Flags
        dos.writeShort(0x0000);
        // Question Count
        dos.writeShort(0x0001);

        // Answer Record Count
        dos.writeShort(0x0000);

        // Authority Record Count
        dos.writeShort(0x0000);

        // Additional Record Count
        dos.writeShort(0x0000);
        String domain = node.getHostName();
        String[] domainParts = domain.split("\\.");

        for (String domainPart : domainParts) {
            byte[] domainBytes = domainPart.getBytes("UTF-8");
            dos.writeByte(domainBytes.length);
            dos.write(domainBytes);
        }
        // No more parts
        dos.writeByte(0x00);

        // Type
        if (DNSType == RecordType.AAAA) {
            dos.writeShort(0x001C);
        } else {
            dos.writeShort(0x0001);
        }

        // Class: IN for our uses
        dos.writeShort(0x0001);
        System.out.println("\n\nQuery ID     " + queryID + " " + domain + "  " +
                DNSType + " --> " + rootServer.getHostAddress());
        return baos.toByteArray();
    }
    /**
     * Retrieves DNS results from a specified DNS server. Queries are sent in iterative mode,
     * and the query is repeated with a new server if the provided one is non-authoritative.
     * Results are stored in the cache.
     *
     * @param node   Host name and record type to be used for the query.
     * @param server Address of the server to be used for the query.
     */
    private static void retrieveResultsFromServer(DNSNode node, InetAddress server) throws IOException {
        byte [] localDnsFrame = dnsFrame;
        socket = new DatagramSocket();
        DatagramPacket dnsReqPacket;
        byte[] buf = new byte[1024];
        DatagramPacket packet = new DatagramPacket(buf, buf.length);
        ResourceRecord rr;
        while (authBit == 0) {

            // Datagram contains root information on first send and target name server on subsequent sends
            try {
                dnsReqPacket = new DatagramPacket(localDnsFrame, localDnsFrame.length, root ? rootServer : server, DEFAULT_DNS_PORT);
                socket.send(dnsReqPacket);
                socket.receive(packet);
                rr = parseBytes(packet, new DNSNode(root ? rootServer.getHostAddress() : server.getHostAddress(), DNSType));
                server = rr.getInetResult();
                root = false;
            } catch (Exception e) {
                resentBit = true;
                throw new IOException();
            }

        }
        switch (dnsAnswer.getType()) {
            case A:
            case AAAA: isIP = true;
                break;
            case SOA:
            case MX:
            case NS:
            case CNAME: isIP = false;
                break;
        }
    }

    /**
     * Parses through what is received and sets the required fields. This is large function however
     * it is necessary to handle the large amount of information is coming in.
     *
     * @param packet            Takes in the packet that is coming in.
     * @param dNode             Allows us to send have a node to manipulate/ ready from when parsing.
     * @return A resource record corresponding to the desired query .
     */
    private static ResourceRecord parseBytes(DatagramPacket packet, DNSNode dNode) throws IOException {
        ByteBuffer bb = ByteBuffer.allocate(1024);
        bb.put(packet.getData(), 0, packet.getLength());
        bb.flip();

        // parse initial header
        int queryID = twoBytesToInt(bb.get(), bb.get());
        short QRcode = qrCodeBit(bb.get(2));
        short OPcode = opCodeBits(bb.get(2));
        authBit = aaBit(bb.get(2));
        short tc = tcBit(bb.get(2));
        short rd = rdBit(bb.get());
        short ra = raBit(bb.get(3));
        short z = zBit(bb.get(3));
        short rCode = rCodeBits(bb.get());
        int qdCount = twoBytesToInt(bb.get(), bb.get());
        int anCount = twoBytesToInt(bb.get(), bb.get());
        int nsCount = twoBytesToInt(bb.get(), bb.get());
        int arCount = twoBytesToInt(bb.get(), bb.get());
        String targetDomain = "";
        RecordType targetType = RecordType.OTHER;
        int targetTTL = 172800;
        if (rCode == 3 || rCode == 5) { throw new IOException(); }


        // parse question field
        for (int i = 0; i < qdCount; i++) {
            String phrase = readLine(bb);
            phrase = phrase.substring(0, phrase.length() - 1);
            targetDomain = phrase;
            int type = twoBytesToInt(bb.get(), bb.get());
            targetType = RecordType.getByCode(type);
            int domainClass = twoBytesToInt(bb.get(), bb.get());
        }
        if (!root) { System.out.println("\n\nQuery ID     " + queryID + " " + targetDomain + "  " +
                DNSType + " --> " + dNode.getHostName()); }
        ResourceRecord rrReturn = new ResourceRecord(targetDomain, targetType, targetTTL, rootServer.getHostAddress());

        if (authBit != 0) {
            System.out.println("Response ID: " + queryID + " Authoritative = true");
        } else {
            System.out.println("Response ID: " + queryID + " Authoritative = false");
        }
        System.out.println("  Answers (" + anCount + ")");


        // parse answer field
        for (int i = 0; i < anCount; i++) {
            String domainPart = readLine(bb);
            domainPart = domainPart.substring(0, domainPart.length() - 1);
            int type = twoBytesToInt(bb.get(), bb.get());
            int domainClass = twoBytesToInt(bb.get(), bb.get());
            long ttl = fourBytesToLong(bb);
            int dataLength = twoBytesToInt(bb.get(), bb.get());
            String ipAddress = "";
            ipAddress = getType(bb, type, ipAddress);
            ResourceRecord rr;
            InetAddress ia;
            switch (type) {
                case 1:
                    ia = InetAddress.getByName(ipAddress);
                    rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, ia);
                    dnsAnswer = rr.getNode();
                    break;
                case 5:
                    rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, ipAddress);
                    dnsAnswer = new DNSNode(ipAddress, RecordType.getByCode(type));
                    break;
                case 6:
                    rr = new ResourceRecord(domainPart, RecordType.A, ttl, ipAddress);
                    dnsAnswer = new DNSNode(ipAddress, RecordType.A);
                    break;
                case 28:
                    rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, ipAddress.toLowerCase());
                    dnsAnswer = rr.getNode();
                    break;
                default:
                    rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, ipAddress);
                }
            rrReturn = rr;
            cache.addResult(rr);
            verbosePrintResourceRecord(rr, type);
        }

        System.out.println("  Nameservers (" + nsCount + ")");
        // parse authoritative field
        for (int i = 0; i < nsCount; i++) {
            String domainPart = readLine(bb);
            domainPart = domainPart.substring(0, domainPart.length() - 1);
            int type = twoBytesToInt(bb.get(), bb.get());
            int domainClass = twoBytesToInt(bb.get(), bb.get());
            long ttl = fourBytesToLong(bb);
            int dataLength = twoBytesToInt(bb.get(), bb.get());
            String dnsName = readLine(bb);
            dnsName = dnsName.substring(0, dnsName.length() - 1);
            ResourceRecord rr;

            // if SOA or MX, cache results and throw error print out
            if (RecordType.getByCode(type) == RecordType.SOA || RecordType.getByCode(type) == RecordType.MX) {
                rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, "----");
                cache.addResult(rr);
                verbosePrintResourceRecord(rr, type);
                resentBit = true;
                System.out.println("  Additional Information (" + arCount + ")");
                throw new IOException();
            } else {
                rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, dnsName);
            }
            cache.addResult(rr);
            verbosePrintResourceRecord(rr, type);
            // Case with only authoritative results, call get results on nameserver and use resulting answers for
            // subsequent calls. Sys out and return statement to ensure proper formatting.
            if (anCount == 0 && arCount == 0 && i == nsCount-1) {
                System.out.println("  Additional Information (" + arCount + ")");
                getResults(new DNSNode(dnsName, RecordType.getByCode(type)), 0);
                authBit = 0;
                return new ResourceRecord(dnsAnswer.getHostName(), DNSType, ttl, InetAddress.getByName(dnsAnswer.getHostName()));
            }

        }
        System.out.println("  Additional Information (" + arCount + ")");
        // parse additional field
        for (int i = 0; i < arCount; i++) {
            String domainPart = readLine(bb);
            domainPart = domainPart.substring(0, domainPart.length() - 1);
            int type = twoBytesToInt(bb.get(), bb.get());
            int domainClass = twoBytesToInt(bb.get(), bb.get());
            long ttl = fourBytesToLong(bb);
            int dataLength = twoBytesToInt(bb.get(), bb.get());
            String ipAddress = "";
            ipAddress = getType(bb, type, ipAddress);
            InetAddress ia = InetAddress.getByName(ipAddress);
            ResourceRecord rr = new ResourceRecord(domainPart, RecordType.getByCode(type), ttl, ia);
            if (type == 1) {
                rrReturn = rr;
            }
            cache.addResult(rr);
            verbosePrintResourceRecord(rr, type);
        }
        return rrReturn;
    }



    /**
     * Helper function used by parse bytes to get the type that is in the packet being received.
     * and handle making the ip to the right format.
     *
     * @param bb             get to the spot in the buffer of where the type is being held.
     * @param ipAddress      A value that will hold the ip that we are parsing
     * @param type          A value that is used from record type to identify the given type.
     *
     *
     * @return        Returns the given IP based on the type without the inserted "/"
     */
    private static String getType(ByteBuffer bb, int type, String ipAddress) {
        switch (type) {
            case 1:  ipAddress = getIP(bb);
                ipAddress = ipAddress.substring(0, ipAddress.length()-1);
                break;
            case 2: break;
            case 5:  ipAddress = readLine(bb);
                ipAddress = ipAddress.substring(0, ipAddress.length()-1);
                break;
            case 6: break;
            case 15: break;
            case 28: ipAddress = getIPv6(bb);
                ipAddress = ipAddress.substring(0, ipAddress.length()-1);
                break;
        }
        return ipAddress;
    }

    /**
     * Helper function used by getType to handle the decoding of IPv6 as it is not the same as IPv4
     *
     * @param bb      get to the spot in the buffer of where the type is being held.
     *
     *
     * @return        Returns the given IP in IPv6, gives it to getType to format correctly.
     */
    private static String getIPv6(ByteBuffer bb) {
        String ip = "";
        for (int i = 0; i < 8; i++) {
            String ipNum = "";
            ipNum += (String.format("%02X", bb.get()));
            ipNum += (String.format("%02X", bb.get()));
            ipNum = ipNum.replaceFirst("^0*", "");
            if (ipNum.equals("")) {
                ip += "0:";
            } else {
                ip += ipNum + ":";
            }
        }
        return ip;
    }

    /**
     * Helper function used by getType to handle the decoding of IPv4
     *
     * @param bb      get to the spot in the buffer of where the type is being held.
     *
     * @return        Returns the given IP in IPv4 format, gives it to getType to format correctly.
     */
    private static String getIP(ByteBuffer bb) {
        String ip = "";
        for (int i = 0; i < 4; i++) {
            int ipNum = (int) (bb.get() & 0xff);
            ip += String.valueOf(ipNum) + ".";
        }
        return ip;
    }

    /**
     * Helper function used by getType and parseBytes to correctly read the value inside a pointer or
     * on the desired line. Recursively calls itself until stop bit is reached (i.e. 00). If "C*" is
     * reached, calls readLineWithOffset to handle pointer.
     *
     * @param bb      get to the spot in the buffer of where the info is being held.
     *
     *
     * @return        Returns the given value of the line as a string.
     */
    private static String readLine(ByteBuffer bb) {
        short len = (short) bb.get();
        String phrase = "";
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {
            int newOffset = twoBytesToInt((byte) (len & 0x3f), bb.get());
            return readLineWithOffset(bb, newOffset);
        }
        for (int j = 0; j < len; j++) {
            phrase += (char) bb.get();
        }
        phrase += ".";
        return phrase + readLine(bb);
    }


    /**
     * Helper function used by functions that require reading a bit that has been referred by pointer.
     *
     * @param offset  get the value of the offset that we want to read from in the DNS response
     * @param bb      get to the spot in the buffer of where the type is being held.
     *
     *
     * @return        Returns the value at the given line based on offset
     */
    private static String readLineWithOffset(ByteBuffer bb, int offset) {
        String phrase = "";
        short len = (short) bb.get(offset);
        if (len == 0) return "";
        if ((len & 0xc0) == 0xc0) {
            int newOffset = twoBytesToInt((byte) (len & 0x3f), bb.get(++offset));
            return readLineWithOffset(bb, newOffset);
        }
        for (int j = 0; j < len; j++) {
            offset++;
            phrase += (char) bb.get(offset);
        }
        phrase += ".";
        offset++;
        return phrase + readLineWithOffset(bb, offset);
    }


    /**
     * The following functions all are used to set the values of the different parts of DNS response
     * and are used by the parseBytes function.
     *
     * @return       the correct size and value of the given bit based on packet.
     */

    private static short aaBit(byte b) {
        return (short) ((b & 0x04) >> 2);
    }

    private static short tcBit(byte b) {
        return (short) ((b & 0x02) >> 1);
    }

    private static short rdBit(byte b) {
        return (short) (b & 0x01);
    }

    private static short raBit(byte b) {
        return (short) ((b & 0x80) >> 7);
    }

    private static short zBit(byte b) {
        return (short) ((b & 0x70) >> 4);
    }
    private static short rCodeBits(byte b) {
        return (short) (b & 0x0F);
    }

    private static short opCodeBits(byte b) {
        return (short) ((b & 0x78) >> 3);
    }
    private static short qrCodeBit(byte b) {
        return (short) ((b & 0x80) >> 7);
    }


    /**
     * The following helpers are used to change values that are read from the response to the correct size and value.
     */
    private static int twoBytesToInt(byte b1, byte b2) {
        int byteInteger = ((b1 << 8) | (b2 & 0xFF));
        return byteInteger & 0xFFFF;
    }

    private static long fourBytesToLong(ByteBuffer b) {
        long l = 0;
        for (int i = 0; i < 3 ; i++) {
            l |= b.get() & 0xFF;
            l <<= 8;
        }
        l |= b.get() & 0xFF;
        return l;
    }

    /**
     * Helper function used to generate the ID for the packet being sent out.
     *
     * @return        the random query ID needed for each DNS request
     */

    private static Integer getQueryId() {
        Integer intQueryID = Math.abs(random.nextInt(65535));
        String queryID = Integer.toHexString(intQueryID);
        return (int) Long.parseLong(queryID, 16);
    }


    /**
     * Helper function used by parseBytes to print the given resource record
     *
     * @param record      printing the record in question based on type.
     * @param rtype       used to distinguish the type of record
     *
     */
    private static void verbosePrintResourceRecord(ResourceRecord record, int rtype) {
        if (verboseTracing)
            System.out.format("       %-30s %-10d %-4s %s\n", record.getHostName(),
                    record.getTTL(),
                    record.getType() == RecordType.OTHER ? rtype : record.getType(),
                    record.getTextResult());
    }

    /**
     * Prints the result of a DNS query.
     *
     * @param node    Host name and record type used for the query.
     * @param results Set of results to be printed for the node.
     */
    private static void printResults(DNSNode node, Set<ResourceRecord> results) {
        if (results.isEmpty())
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), -1, "0.0.0.0");
        for (ResourceRecord record : results) {
            System.out.printf("%-30s %-5s %-8d %s\n", node.getHostName(),
                    node.getType(), record.getTTL(), record.getTextResult());
        }
    }
}
