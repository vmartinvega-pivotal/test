package io.external.codec.impl.adapter;



import io.external.codec.impl.domain.SipdrTekInformationElement;
import io.external.codec.impl.loader.MsisdnImsiMapping;
import io.external.codec.utils.DatacastVersionUtils;
import io.pivotal.rti.codec.support.ByteStream;
import io.pivotal.rti.protocols.AbstractProtocolAdapter;
import io.pivotal.rti.protocols.ProtocolEvent;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.Random;

import org.apache.commons.lang3.exception.ExceptionUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.jmx.export.annotation.ManagedResource;

import com.emc.rti.util.imsi.IMSIUtil;
import com.emc.rti.util.uuid.IDGenerator;
import com.emc.rti.util.uuid.ReentrantLockingUUIDGenerator;

@ManagedResource
public class DatacastSipdrIngestorProtocolAdapter extends
		AbstractProtocolAdapter {

	private final int versionId;
	private final String protocolName;
	private static IDGenerator uuidGenerator = new ReentrantLockingUUIDGenerator();
	private static final Logger LOGGER = LoggerFactory
			.getLogger(DatacastSipdrIngestorProtocolAdapter.class);

	// 29_1
	// A209 TransStats SIP TekIE
	// TranactionStatInfoNew
	
	private static MsisdnImsiMapping msisdnToImsiMapping = MsisdnImsiMapping.getInstance();


	public DatacastSipdrIngestorProtocolAdapter(String version,
			String protocolName, String folder) {
		super(protocolName);
		LOGGER.info("Invocation constructor v7.");
		this.versionId = DatacastVersionUtils.fromString(version);
		if ((this.versionId != 1) && (this.versionId != 2)
				&& (this.versionId != 3) && (this.versionId != 4)
				&& (this.versionId != 5) && (this.versionId != 6)
				&& (this.versionId != 7 && (this.versionId != 8))) {
			throw new IllegalArgumentException("Unsupported datacast version: "
					+ this.getVersion());
		}
		this.protocolName = protocolName;
		//msisdnToImsiMapping = new MsisdnImsiMapping();
		msisdnToImsiMapping.setFolder(folder);
	}

	@Override
	public String getVersion() {
		return DatacastVersionUtils.VERSIONS[this.versionId];
	}

	@Override
	public Collection<ProtocolEvent> bytesToProtocolEvent(byte[] bytes)
			throws IOException {
		List<ProtocolEvent> events = readOHDR(bytes);
		try {
			if (events != null) {
				
				Random r = new Random();
				int num =0;
				for (ProtocolEvent event : events) {
					String msisdn = (String) event.getProtocolDetails().get(
							"msisdn");
					int callType = event.getProtocolDetails().get(
							"callType")!=null?(int) event.getProtocolDetails().get(
							"callType"): 0;
					String imsi = msisdnToImsiMapping.getImsiForMsisdn(msisdn);
					if (imsi != null) {
						event.setPrimaryId(imsi);
					}
					else if(callType == 1664)//callType
					{
						num = 10000 + r.nextInt(50000);//it will always give 5 digit number ,range 10000-60000 
						imsi = "9999999999"+num;
						//LOGGER.info("No imsi-msisdn mapping for {} , {} ",imsi,msisdn);
						event.setPrimaryId(imsi);
					}

				}
			} else {
				LOGGER.warn("List of events is null!");
			}
		} catch (Throwable t) {
			LOGGER.info("Exception occured while try to perform mapping : {}", t.getMessage());
			ExceptionUtils.printRootCauseStackTrace(t);
		}
		return events;
	}

	public List<ProtocolEvent> readOHDR(byte[] b) throws IOException {
		LOGGER.debug(" Reading OHDR header ");
		ByteStream bs = new ByteStream(b, b.length, 0);
		long len = bs.readUnsignedInt();
		if (len + 4L != b.length) {
			throw new IllegalStateException("Invalid message size.");
		}
		int drCount = readOHDRheader(bs, b);

		List<ProtocolEvent> listOhdrRec = readOHDRRecords(drCount, bs);
		return listOhdrRec;
	}

	public int readOHDRheader(ByteStream bs, byte[] b) throws IOException {

		if (bs.readUnsignedByte() != 130) {
			throw new IllegalStateException("Invalid message type.");
		}

		bs.skipBytes(3);
		int drCount = bs.readUnsignedByte(); // If 0 then NO data section
												// appear. DR<-HearderFixed (2
												// bytes)+ DR-HearderFixed (n
												// bytes)->
		bs.skipBytes(3);
		return drCount;
	}

	public List<ProtocolEvent> readOHDRRecords(int drCount, ByteStream bs)
			throws IOException {
		LOGGER.debug(" Reading OHDR records ");
		List<ProtocolEvent> events = new ArrayList<ProtocolEvent>(drCount);
		String correlationBatchId = uuidGenerator.generateStringID();

		for (int i = 0; i != drCount; i++) {
			int mark = bs.mark();// 12
			int drLen = bs.readUnsignedShort() * 4; // 181
			ProtocolEvent protocolEvent = readRecord(bs);
			protocolEvent.getProtocolDetails().put("rti.correlationBatchId",
					correlationBatchId);
			protocolEvent.getProtocolDetails().put("rti.correlationIndex", i);
			events.add(protocolEvent);
			bs.reset(mark);
			bs.skipBytes(drLen);
		}
		return events;
	}

	private ProtocolEvent readRecord(ByteStream bs) throws IOException {
		ProtocolEvent event = new ProtocolEvent();
		event.setProtocolName(protocolName);
		// TODO
		event.setProtocolType((short) 10);
		event.setKey(uuidGenerator.generateStringID());

		int bitmask = bs.readUnsignedByte();
		if ((bitmask & 0x7) != 4) {
			throw new IllegalStateException("Not a Sipdr message.");
		}
		int elementNum = bitmask >>> 3 & 0x3; // Number of element ID mask used
												// in next fixed section.

		if ((bitmask & 0xE0) >>> 5 != 1) {
			throw new IllegalStateException(
					" Expected value of parameter must be 1 ");
		}
		int elementsize = bs.readUnsignedByte() * 4; // Length of entire element
														// section -> 4 bytes
		int mark = bs.mark();

		readContent(elementNum, bs, event);

		bs.reset(mark);
		bs.skipBytes(elementsize);
		int variableSectionLength = bs.readUnsignedShort();
		int ieCount = bs.readUnsignedShort(); // Total number of variable fields
												// present
		int formatId = bs.readUnsignedShort();

		boolean first = true;
		StringBuilder iesb = new StringBuilder();

		SipdrTekInformationElement sipdrTekInformationElement=new SipdrTekInformationElement();
		setSipdrTekInformationElementDeafaultValues(sipdrTekInformationElement);

		for (int i = 0; i != ieCount; i++) {
			mark = bs.mark();
			// Variable information
			int dataId = bs.readUnsignedShort(); // Identifies data type

			// Variable field detection (VFD)
			int encodedDataId = (int) ((dataId & 0xC000) >> 14); // most
																	// significant
																	// bit 15,16
																	// give
																	// Encoded
																	// Data Id
			String format = "";
			if (encodedDataId == 0 || encodedDataId == 1 || encodedDataId == 3)
				format = "IE";
			else if (encodedDataId == 2) // Variable field encoded in format 3
											// can be IE or TEKIE depends on
											// content of 3rd byte of stream
			{
				int thirdByteValueBitmask = bs.readUnsignedByte();

				if (thirdByteValueBitmask == 128)
					format = "TEKIE";
				else
					format = "IE";
			}
			bs.reset(mark);
			// VFD - end

			// IE variable
			if (format.equals("IE")) {

				if (encodedDataId == 0) { // Format 1
					int dataid = bs.readUnsignedShort();
					int sz = bs.readUnsignedByte(); // Size of data field in
													// number of bytes

					mark = bs.mark();
					bs.reset(mark);

					if (first) {
						first = false;
					} else {
						iesb.append(";");
					}
					iesb.append(dataid);
					iesb.append("=");
					iesb.append(bs.readBytesAsHex(sz)); // get data field
				} else if (encodedDataId == 1) { // Format 2

					int dataid = bs.readUnsignedShort();
					int totalLength = bs.readUnsignedShort(); // TODO total
																// length --
																// Need
																// clarification
																// !
					// int iterationNumber=bs.readUnsignedByte(); // TODO
					// iteration part -- Need clarification !
					// int sz = bs.readUnsignedByte(); // Size of data field in
					// number of bytes // 22_1

					mark = bs.mark();
					bs.reset(mark);

					if (first) {
						first = false;
					} else {
						iesb.append(";");
					}
					iesb.append(dataid);
					iesb.append("=");
					// iesb.append(bs.readBytesAsHex(sz)); // 22_1
					iesb.append(bs.readBytesAsHex(totalLength));

				} else if (encodedDataId == 2) { // Format 3

					int dataid = bs.readUnsignedShort();
					int totalLength = bs.readUnsignedShort(); // TODO total
																// length --
																// Need
																// clarification
					// int sz = bs.readUnsignedByte(); // Size of data field in
					// number of bytes // 22_1 behalf of shared example

					if (first) {
						first = false;
					} else {
						iesb.append(";");
					}
					iesb.append(dataid);
					iesb.append("=");
					// iesb.append(bs.readBytesAsHex(sz)); // get data field
					iesb.append(bs.readBytesAsHex(totalLength)); // 22_1 behalf
																	// of shared
																	// example

					/*
					 * int varBitmask = bs.readUnsignedByte(); // 22_1 behalf of
					 * shared example
					 * 
					 * if ((varBitmask & 0x1) != 0) { // bit 1 of variable
					 * Bitmask -> optional parameter Timestamp (sec) sz += 4; }
					 * if ((varBitmask & 0x2) != 0) { // bit 2 of variable
					 * Bitmask -> optional parameter Timestamp (usec) sz += 4; }
					 */
					mark = bs.mark();
					bs.reset(mark);
				} else if (encodedDataId == 3) { // Format 4

					int dataid = bs.readUnsignedShort();
					int totalLength = bs.readUnsignedShort(); // TODO total
																// length --
																// Need
																// clarification
																// ! Should we
																// use for SKIP
																// bytes !
					// int iterationNumber=bs.readUnsignedByte(); // TODO
					// iteration part -- Need clarification !
					// int sz = bs.readUnsignedByte(); // Size of data field in
					// number of bytes

					mark = bs.mark();
					bs.reset(mark);

					if (first) {
						first = false;
					} else {
						iesb.append(";");
					}
					iesb.append(dataid);
					iesb.append("=");
					// iesb.append(bs.readBytesAsHex(sz)); // get data field
					// 22_1
					iesb.append(bs.readBytesAsHex(totalLength));

					// int varBitmask = bs.readUnsignedByte(); // 22_1

					/*
					 * if ((varBitmask & 0x1) != 0) { // bit 1 of variable
					 * Bitmask -> optional parameter Timestamp (sec) sz += 4; }
					 * if ((varBitmask & 0x2) != 0) { // bit 2 of variable
					 * Bitmask -> optional parameter Timestamp (usec) sz += 4; }
					 */
					mark = bs.mark();
					bs.reset(mark);
					//event.getProtocolDetails().put("informationElements", iesb.toString());
				}
				// IE - SIP parameters values NOT required in SIP DR ingester.
				// IE - DataCast SIP format NOT required in SIPDR ingester.
				// IRIS variable Field (TekIE)
			} else if (format.equals("TEKIE")) {
				int dataid = bs.readUnsignedShort();
				int thirdByteValueBitmask = bs.readUnsignedByte();
				int sz = bs.readUnsignedByte(); // length of data field
				// 22_1
				bs.skipBytes(sz); // skip length part
				// Add common logic for TEKIE
				int totalLengthTEKpart = bs.readUnsignedShort(); // Total length
																	// of TEKIE
																	// contents
				long tekBitmask = bs.readUnsignedInt();
				// End common logic for TEKIE
				// 22_1 end
				if (((thirdByteValueBitmask & 0x80) >> 7) != 0) {
					readTekIEPart(dataid, bs, event, tekBitmask,sipdrTekInformationElement);
				}

				mark = bs.mark();
				bs.reset(mark);
			}
		}
		// A209
			event.getProtocolDetails().put("transactionStatInfoNewTransactionType",
			sipdrTekInformationElement.getTransactionStatInfoNewTransactionType());
					event.getProtocolDetails().put("transactionStatInfoNewStartTime",
			sipdrTekInformationElement.getTransactionStatInfoNewStartTime());
					event.getProtocolDetails().put("transactionStatInfoNewEndTime",
			sipdrTekInformationElement.getTransactionStatInfoNewEndTime());
					event.getProtocolDetails().put("transactionStatInfoNewCauseCodes",
			sipdrTekInformationElement.getTransactionStatInfoNewCauseCodes());
					event.getProtocolDetails().put("transactionStatBits",
			sipdrTekInformationElement.getTransactionStatBits());
					event.getProtocolDetails().put(
			"transactionStatInfoNewTransactionDirection",
			sipdrTekInformationElement.getTransactionStatInfoNewTransactionDirection());
					event.getProtocolDetails().put("transactionStatInfoNewProtocolId",
			sipdrTekInformationElement.getTransactionStatInfoNewProtocolId());
					event.getProtocolDetails().put("transactionStatInfoNewSourceIp",
			sipdrTekInformationElement.getTransactionStatInfoNewSourceIp());
					event.getProtocolDetails().put("transactionStatInfoNewSourcePort",
			sipdrTekInformationElement.getTransactionStatInfoNewSourcePort());
					event.getProtocolDetails().put("transactionStatInfoNewDestinationIp",
			sipdrTekInformationElement.getTransactionStatInfoNewDestinationIp());
					event.getProtocolDetails().put("transactionStatInfoNewDestinationPort",
			sipdrTekInformationElement.getTransactionStatInfoNewDestinationPort());
					event.getProtocolDetails().put("transactionStatInfoNewOperationBits",
			sipdrTekInformationElement.getTransactionStatInfoNewOperationBits());
					event.getProtocolDetails().put("transactionStatInfoNewBitsExtention",
			sipdrTekInformationElement.getTransactionStatInfoNewBitsExtention());
					event.getProtocolDetails().put("transactionStatInfoNewVlanlds",
			sipdrTekInformationElement.getTransactionStatInfoNewVlanlds());
					event.getProtocolDetails().put("transactionStatReasonHeaderDataList",
			sipdrTekInformationElement.getTransactionStatReasonHeaderDataList());
					event.getProtocolDetails().put(
			"transactionStatIsupCauseIndicatorsDataList",
			sipdrTekInformationElement.getTransactionStatIsupCauseIndicatorsDataList());
					event.getProtocolDetails().put("transactionStatPaniCellIdDataList",
			sipdrTekInformationElement.getTransactionStatPaniCellIdDataList());
					event.getProtocolDetails().put(
			"transactionStatSipTimerFirstRingingTime",
			sipdrTekInformationElement.getTransactionStatSipTimerFirstRingingTime());
					event.getProtocolDetails().put(
			"transactionStatSipTimerLastRingingTime",
			sipdrTekInformationElement.getTransactionStatSipTimerLastRingingTime());
					event.getProtocolDetails().put("transactionStatSipTimerAnswerTime",
			sipdrTekInformationElement.getTransactionStatSipTimerAnswerTime());
					event.getProtocolDetails().put(
			"transactionStatSipTimerAnswerConfirmTime",
			sipdrTekInformationElement.getTransactionStatSipTimerAnswerConfirmTime());
					event.getProtocolDetails().put(
			"transactionStatSipTimerCancelTerminatedTime",
			sipdrTekInformationElement.getTransactionStatSipTimerCancelTerminatedTime());
					event.getProtocolDetails().put("transactionStatPttinfoPocSessionType",
			sipdrTekInformationElement.getTransactionStatPttinfoPocSessionType());
					event.getProtocolDetails().put("transactionStatPttinfoFeatureTag1",
			sipdrTekInformationElement.getTransactionStatPttinfoFeatureTag1());
			// A208
			event.getProtocolDetails().put("pANICellIdList", sipdrTekInformationElement.getpANICellIdList());

		if (sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues().size() != 0) {
			//N_PRM00434437A - To resolve problem : NullPointerException.
			if(sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues().contains(null))
				sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues().remove(null);
			//
			int length = sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues().size();

			String firstOccerence = (String) sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues()
					.get(0);
			String lastOccerence = "";

			if (length > 1)
				lastOccerence = lastOccerence
						.concat((String) sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues()
								.get(length - 1));
			else
				lastOccerence = firstOccerence;

			if (firstOccerence.contains("|")) {
				int mulFirstOccerenceBreak = firstOccerence.indexOf("|");
				firstOccerence = firstOccerence.substring(0,
						mulFirstOccerenceBreak);
			}

			if (lastOccerence.contains("|")) {
				int mulLastOccerenceBreak = lastOccerence.indexOf("|");
				lastOccerence = lastOccerence.substring(0,
						mulLastOccerenceBreak);
			}

			int firstOccerenceLength = firstOccerence.length();
			int lastOccerenceLength = lastOccerence.length();

			if (firstOccerenceLength > 18) {
				firstOccerence = firstOccerence.substring(10); // 3236323032
																// 61643366
																// 30613237613033
				
				String firstLacString = firstOccerence.substring(0, 8);
				String firstLacAsciiValue = stringToHex(firstLacString);
				// Z_PRM00438414A
				try{
				int firstLacValue = Integer.parseInt(firstLacAsciiValue, 16);				
				event.getProtocolDetails().put("firstLac", firstLacValue);
				}
				catch(Exception e){
					event.getProtocolDetails().put("firstLac", 0);
				}
				
				String firstCellIdString = firstOccerence.substring(8);
				String firstCellIdAsciiValue = stringToHex(firstCellIdString);
				// unable to save big value like ffffffff Hex-> int big value
				if(firstCellIdAsciiValue.length()>=8){
					firstCellIdAsciiValue="0";
				}
				//
				//Z_PRM00438414A
				try{
				int firstCellIdValue = Integer.parseInt(firstCellIdAsciiValue,
						16);
				event.getProtocolDetails().put("firstCellId", firstCellIdValue);
				}
				catch(Exception e){
					event.getProtocolDetails().put("firstCellId", 0);
				}
			}

			if (lastOccerenceLength > 18) {
				lastOccerence = lastOccerence.substring(10);
				String lastLacString = lastOccerence.substring(0, 8);
				String lastLacAsciiValue = stringToHex(lastLacString);
				try{	//Z_PRM00438414A
				int lastLacValue = Integer.parseInt(lastLacAsciiValue, 16);
				event.getProtocolDetails().put("lac", lastLacValue);
				}
				catch(Exception e){
					event.getProtocolDetails().put("lac", 0);
				}

				String lastCellIdString = lastOccerence.substring(8);
				String lastCellIdAsciiValue = stringToHex(lastCellIdString);
				// unable to save big value like ffffffff Hex-> int big value
				if(lastCellIdAsciiValue.length()>=8){
					lastCellIdAsciiValue="0";
				}
				//
				try{	//Z_PRM00438414A
				int lastCellIdValue = Integer
						.parseInt(lastCellIdAsciiValue, 16);
				event.getProtocolDetails().put("cellId", lastCellIdValue);
				}
				catch(Exception e){
					event.getProtocolDetails().put("cellId", 0);
				}
			}

		}

		// event.getProtocolDetails().put("informationElements",
		// iesb.toString()); // 22_1 Not required

		if (event.getPrimaryId() != null) {
			String mccmnc = IMSIUtil.extractMccMnc(event.getPrimaryId());
			event.getProtocolDetails().put("mccmnc", mccmnc);
			if ((mccmnc != null) && mccmnc.length() >= 5) {
				event.getProtocolDetails().put("mcc", mccmnc.substring(0, 3));
				event.getProtocolDetails().put("mnc", mccmnc.substring(3));
			}
		}
		// Randomly added IMSI
		/*
		 * Random rm = new Random(); for(int i=0;i<1;i++){
		 * 
		 * if(!event.getProtocolDetails().containsKey("imsi")){ String s
		 * =""+rm.nextInt(9); if(!s.equals("0"))
		 * event.getProtocolDetails().put("imsi", s); else
		 * event.getProtocolDetails().put("imsi", "10"); }
		 * LOGGER.debug("fetched  imsi value from protocol details map  ::::::   "
		 * +event.getProtocolDetails().get("imsi")); }
		 */
		// END
		LOGGER.debug("Extracted event ::::::   " + event);
		return event;
	}

	String stringToHex(String input) {
		String hex = input;
		StringBuilder output = new StringBuilder();
		for (int i = 0; i < hex.length(); i += 2) {
			String str = hex.substring(i, i + 2);
			output.append((char) Integer.parseInt(str, 16));
		}
		return output.toString();
	}

	public void readTekIEPart(int dataid, ByteStream bs, ProtocolEvent event,
			long tekBitmask,SipdrTekInformationElement sipdrTekInformationElement) throws IOException {

		String transactionStatInfoNewTransactionType =sipdrTekInformationElement.getTransactionStatInfoNewTransactionType();
		String transactionStatInfoNewStartTime =sipdrTekInformationElement.getTransactionStatInfoNewStartTime();
		String transactionStatInfoNewEndTime=sipdrTekInformationElement.getTransactionStatInfoNewEndTime();
		String transactionStatInfoNewCauseCodes=sipdrTekInformationElement.getTransactionStatInfoNewCauseCodes();
		String transactionStatBits=sipdrTekInformationElement.getTransactionStatBits();
		String transactionStatInfoNewTransactionDirection=sipdrTekInformationElement.getTransactionStatInfoNewTransactionDirection();
		String transactionStatInfoNewProtocolId=sipdrTekInformationElement.getTransactionStatInfoNewProtocolId();
		String transactionStatInfoNewSourceIp=sipdrTekInformationElement.getTransactionStatInfoNewSourceIp();
		String transactionStatInfoNewSourcePort=sipdrTekInformationElement.getTransactionStatInfoNewSourcePort();
		String transactionStatInfoNewDestinationIp=sipdrTekInformationElement.getTransactionStatInfoNewDestinationIp();
		String transactionStatInfoNewDestinationPort=sipdrTekInformationElement.getTransactionStatInfoNewDestinationPort();
		String transactionStatInfoNewOperationBits=sipdrTekInformationElement.getTransactionStatInfoNewOperationBits();
		String transactionStatInfoNewBitsExtention=sipdrTekInformationElement.getTransactionStatInfoNewBitsExtention();
		String transactionStatInfoNewVlanlds=sipdrTekInformationElement.getTransactionStatInfoNewVlanlds();
		// ReasonHeaders
		String transactionStatReasonHeaderDataList=sipdrTekInformationElement.getTransactionStatReasonHeaderDataList();
		// isupCauseIndicators
		String transactionStatIsupCauseIndicatorsDataList=sipdrTekInformationElement.getTransactionStatIsupCauseIndicatorsDataList();
		// panCellIdDataList
		String transactionStatPaniCellIdDataList=sipdrTekInformationElement.getTransactionStatPaniCellIdDataList();
		// sip titransactionStatPaniCellIdDataList
		String transactionStatSipTimerFirstRingingTime=sipdrTekInformationElement.getTransactionStatSipTimerFirstRingingTime();
		String transactionStatSipTimerLastRingingTime=sipdrTekInformationElement.getTransactionStatSipTimerLastRingingTime();
		String transactionStatSipTimerAnswerTime=sipdrTekInformationElement.getTransactionStatSipTimerAnswerTime();
		String transactionStatSipTimerAnswerConfirmTime=sipdrTekInformationElement.getTransactionStatSipTimerAnswerConfirmTime();
		String transactionStatSipTimerCancelTerminatedTime=sipdrTekInformationElement.getTransactionStatSipTimerCancelTerminatedTime();
		// pttinfo
		String transactionStatPttinfoPocSessionType=sipdrTekInformationElement.getTransactionStatPttinfoPocSessionType();
		String transactionStatPttinfoFeatureTag1=sipdrTekInformationElement.getTransactionStatPttinfoFeatureTag1();
		// A209 end
		// A208
		String pANICellIdList=sipdrTekInformationElement.getpANICellIdList();
		// 29_1 end
		boolean btransactionStatInfoNewTransactionType=sipdrTekInformationElement.isBtransactionStatInfoNewTransactionType();
		boolean btransactionStatInfoNewStartTime=sipdrTekInformationElement.isBtransactionStatInfoNewStartTime();
		boolean btransactionStatInfoNewEndTime=sipdrTekInformationElement.isBtransactionStatInfoNewEndTime();
		boolean btransactionStatInfoNewCauseCodes=sipdrTekInformationElement.isBtransactionStatInfoNewCauseCodes();
		boolean btransactionStatBits=sipdrTekInformationElement.isBtransactionStatBits();
		boolean btransactionStatInfoNewTransactionDirection=sipdrTekInformationElement.isBtransactionStatInfoNewTransactionDirection();
		boolean btransactionStatInfoNewProtocolId=sipdrTekInformationElement.isBtransactionStatInfoNewProtocolId();
		boolean btransactionStatInfoNewSourceIp=sipdrTekInformationElement.isBtransactionStatInfoNewSourceIp();
		boolean btransactionStatInfoNewSourcePort=sipdrTekInformationElement.isBtransactionStatInfoNewSourcePort();
		boolean btransactionStatInfoNewDestinationIp=sipdrTekInformationElement.isBtransactionStatInfoNewDestinationIp();
		boolean btransactionStatInfoNewDestinationPort=sipdrTekInformationElement.isBtransactionStatInfoNewDestinationPort();
		boolean btransactionStatInfoNewOperationBits=sipdrTekInformationElement.isBtransactionStatInfoNewOperationBits();
		boolean btransactionStatInfoNewBitsExtention=sipdrTekInformationElement.isBtransactionStatInfoNewBitsExtention();
		boolean btransactionStatInfoNewVlanlds=sipdrTekInformationElement.isBtransactionStatInfoNewVlanlds();
		// ReasonsHeaders
		boolean btransactionStatReasonHeaderDataList=sipdrTekInformationElement.isBtransactionStatReasonHeaderDataList();
		// isupCauseIndicators
		boolean btransactionStatIsupCauseIndicatorsDataList=sipdrTekInformationElement.isBtransactionStatIsupCauseIndicatorsDataList();
		// panCellId
		boolean btransactionStatPaniCellIdDataList=sipdrTekInformationElement.isBtransactionStatPaniCellIdDataList();
		// transactionStatSipTimer
		boolean btransactionStatSipTimerFirstRingingTime=sipdrTekInformationElement.isBtransactionStatSipTimerFirstRingingTime();
		boolean btransactionStatSipTimerLastRingingTime=sipdrTekInformationElement.isBtransactionStatSipTimerLastRingingTime();
		boolean btransactionStatSipTimerAnswerTime=sipdrTekInformationElement.isBtransactionStatSipTimerAnswerTime();
		boolean btransactionStatSipTimerAnswerConfirmTime=sipdrTekInformationElement.isBtransactionStatSipTimerAnswerConfirmTime();
		boolean btransactionStatSipTimerCancelTerminatedTime=sipdrTekInformationElement.isBtransactionStatSipTimerCancelTerminatedTime();
		// pttinfo
		boolean btransactionStatPttinfoPocSessionType=sipdrTekInformationElement.isBtransactionStatPttinfoPocSessionType();
		boolean btransactionStatPttinfoFeatureTag1=sipdrTekInformationElement.isBtransactionStatPttinfoFeatureTag1();
		// A208
		boolean bpANICellIdList=sipdrTekInformationElement.isBpANICellIdList();

		List transactionStatPaniCellIdDataListValues = sipdrTekInformationElement.getTransactionStatPaniCellIdDataListValues();
		
		if (dataid == 41474) {
			LOGGER.debug(" tecie voice quality metrics ");
			if ((tekBitmask & 1L) != 0L) {
				String metricType = bs.readStringAsHex(); // This call (a) first
															// get length of
															// actual content
															// (Value of first
															// byte) (b) get
															// value as per
															// content length.
				event.getProtocolDetails().put("voiceQualityMetricsType",
						metricType);
			}
			if ((tekBitmask & 0x2) != 0L) {
				String direction = bs.readStringAsHex();
				event.getProtocolDetails().put("voiceQualityMetricsDirection",
						direction);
			}
			if ((tekBitmask & 0x4) != 0L) {
				String severity = bs.readStringAsHex();
				event.getProtocolDetails().put("voiceQualityMetricSeverity",
						severity);
			}

			if ((tekBitmask & 0x8) != 0L) {

				long bitmask3 = bs.readUnsignedShort();

				if ((bitmask3 & 1L) != 0L) {
					String callId = bs.readStringAsHex(); // This call (a) first
															// get length of
															// actual content
															// (Value of first
															// byte) (b) get
															// value as per
															// content length.
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoCallId", callId);
				}
				if ((bitmask3 & 0x2) != 0L) {
					String localId = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoLocalId", localId);
				}
				if ((bitmask3 & 0x4) != 0L) {
					String remoteId = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoRemoteId", remoteId);
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoOrigid",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoLocalAddr",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoRemoteAddr",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoLocalGroupId",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoRemoteGroupid",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoLocalMacAddr",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x200) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionInfoRemoteMacAddr",
							bs.readStringAsHex());
				}
			}
			//Voice Quality Dialog ID
			if ((tekBitmask & 0x10) != 0L) {
				LOGGER.info("  Voice Quality Dialog ID tecie voice quality metrics ");

				long bitmask5 = bs.readUnsignedShort();
				LOGGER.info("  Voice Quality Dialog ID tecie voice quality metrics bitmask "+bitmask5);

				if ((bitmask5 & 1L) != 0L) {
					String callId = bs.readStringAsHex(); // This call (a) first
															// get length of
															// actual content
															// (Value of first
															// byte) (b) get
															// value as per
															// content length.
					event.getProtocolDetails().put(
							"voiceQualityDialogIdCallId", callId);
					LOGGER.info("  Voice Quality Dialog ID tecie voice quality metrics callId "+callId);

				}
				if ((bitmask5 & 0x2) != 0L) {
					String totag = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"voiceQualityDialogIdToTag", totag);
					LOGGER.info("  Voice Quality Dialog ID tecie voice quality metrics totag "+totag);

				}
				if ((bitmask5 & 0x4) != 0L) {
					String fromTag = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"voiceQualityDialogIdFromTag", fromTag);
					LOGGER.info("  Voice Quality Dialog ID tecie voice quality metrics fromTag "+fromTag);

				}
				if ((bitmask5 & 0x8) != 0L) {
					String didParm = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"voiceQualityDialogIdDidParm",
							didParm);
					LOGGER.info("  Voice Quality Dialog ID tecie voice quality metrics didParm "+didParm);

				}
			}
		} else if (dataid == 41475) {
			LOGGER.debug(" tecie local voice quality metrics ");
			String val = "";
			if ((tekBitmask & 1L) != 0L) {
				val = String.valueOf(bs.readLong());
			}
			val = "";
			event.getProtocolDetails().add("localVoiceQualityMetricsStartTime",
					val);
			if ((tekBitmask & 0x2) != 0L) {
				val = String.valueOf(bs.readLong());
			}
			event.getProtocolDetails().add("localVoiceQualityMetricsEndTime",
					val);

			if ((tekBitmask & 0x4) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescPayloadType",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescPayloadDesc",
							bs.readStringAsHex());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescSampleRate",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescPacketsPerSec",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescFrameDuration",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescFrameOctets",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescFramePerPacket",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescFmtpOptions",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescPktLossConcealment",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x200) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySessionDescSilenceSupperessionState",
							bs.readStringAsHex());
				}
			}
			if ((tekBitmask & 0x8) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityJitterBufferAdaptive",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityJitterBufferRate",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityJitterBufferNominal",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails()
							.put("voiceQualityJitterBufferMax",
									bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityJitterBufferAbsMax",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityJitterBufferIncrease",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityJitterBufferDecrease",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x10) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityPacketLossRate", bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityPacketDiscardRate",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityPacketCumulativeLoss",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put("voiceQualityPacketLossMax",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityPacketDiscardMax",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x20) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityBursttLossDensity",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put("voiceQualityBurstDuration",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityBurstGapLossDensity",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityBurstGapDuration",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityBurstMinThreshold",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x40) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityRoundTripDelay", bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEndSystemDelay", bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put("voiceQualityOneWayDelay",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails()
							.put("voiceQualitySymmOneWayDelay",
									bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityDelayInterarrivalJitter",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityDelayMeanAbsoluteJitter",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityDelayMaxJitter", bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityMaxRoundTripDelay",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityMaxOneWayDelay", bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x80) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put("voiceQualitySignalLevel",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySignalNoiseLevel",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualitySignalResidualEchoReturnLoss",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x100) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"voiceListeningQualityEstimate",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x2) != 0L) {
					String rlqEstAlg = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"voiceQualityEstimatRlqEstAlg", rlqEstAlg);
				}
				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateConversationalQuality",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateRcqEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateExternalRIn",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateExtRiEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateExternalROut",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateEstRoEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put("voiceQualityEstimateMosIq",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x200) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateMosIqEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x400) != 0L) {
					event.getProtocolDetails().put("voiceQualityEstimateMosCq",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x800) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateMosCqEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x1000) != 0L) {
					event.getProtocolDetails().put(
							"voiceQualityEstimateQoeEstAlg",
							bs.readStringAsHex());
				}
			}
			if ((tekBitmask & 0x200) != 0L) {
				event.getProtocolDetails().put("gatewaySerielNumber",
						bs.readStringAsHex());
			}
			if ((tekBitmask & 0x400) != 0L) {
				event.getProtocolDetails().put("noRtcpReceived",
						bs.readStringAsHex());
			}
		} else if (dataid == 41476) {
			LOGGER.debug(" tecie remote voice quality metrics ");

			String val = "";
			if ((tekBitmask & 1L) != 0L) {
				val = String.valueOf(bs.readLong());
			}
			val = "";
			event.getProtocolDetails().add("remoteVoiceQualityStartTime", val);
			if ((tekBitmask & 0x2) != 0L) {
				val = String.valueOf(bs.readLong());
			}
			event.getProtocolDetails().add("remoteVoiceQualityEndTime", val);

			if ((tekBitmask & 0x4) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionPayloadType",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionPayloadDesc",
							bs.readStringAsHex());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionSampleRate",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionPacketsPerSec",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionFrameDuration",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionFrameOctets",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionFramePerPacket",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionFmtpOptions",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySessionPktLossConcealment",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x200) != 0L) {
					event.getProtocolDetails()
							.put("remoteVoiceQualitySessionSilenceSupperessionState",
									bs.readStringAsHex());
				}
			}
			if ((tekBitmask & 0x8) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferAdaptive",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferRate",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferNominal",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferMax",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferAbsMax",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferIncrease",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityJitterBufferDecrease",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x10) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityPacketLossRate",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityPacketDiscardRate",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityPacketCumulativeLoss",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityPacketLossMax",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityPacketDiscardMax",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x20) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityBursttLossDensity",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityBurstDuration",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityBurstGapLossDensity",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityBurstGapDuration",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityBurstMinThreshold",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x40) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityRoundTripDelay",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEndSystemDelay",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityOneWayDelay",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySymmOneWayDelay",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityInterarrivalJitter",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityMeanAbsoluteJitter",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails()
							.put("remoteVoiceQualityMaxJitter",
									bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityMaxRoundTripDelay",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityMaxOneWayDelay",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x80) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualitySignalLevel",
							bs.readUnsignedInt());
				}
				if ((bitmask3 & 0x2) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityNoiseLevel",
							bs.readUnsignedInt());
				}

				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityResidualEchoReturnLoss",
							bs.readUnsignedInt());
				}
			}
			if ((tekBitmask & 0x100) != 0L) {
				long bitmask3 = bs.readUnsignedShort();
				if ((bitmask3 & 1L) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceListeningQuality",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x2) != 0L) {
					String rlqEstAlg = bs.readStringAsHex();
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimatRlqEstAlg", rlqEstAlg);
				}
				if ((bitmask3 & 0x4) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityErsatiremoteVoiceQuality",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x8) != 0L) {
					event.getProtocolDetails().put(
							"remotremoteVoiceQualityyyEstimateRcqEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x10) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateExternalRIn",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x20) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateExtRiEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x40) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateExternalROut",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x80) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateEstRoEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x100) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateMosIq",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x200) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateMosIqEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x400) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateMosCq",
							bs.readUnsignedShort());
				}
				if ((bitmask3 & 0x800) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateMosCqEstAlg",
							bs.readStringAsHex());
				}
				if ((bitmask3 & 0x1000) != 0L) {
					event.getProtocolDetails().put(
							"remoteVoiceQualityEstimateQoeEstAlg",
							bs.readStringAsHex());
				}
			}
			if ((tekBitmask & 0x200) != 0L) {
				event.getProtocolDetails().put(
						"remoteVoiceQualityGatewaySerielNumber",
						bs.readStringAsHex());
			}
			if ((tekBitmask & 0x400) != 0L) {
				event.getProtocolDetails().put(
						"remoteVoiceQualityNoRtcpReceived",
						bs.readStringAsHex());
			}
		} else if (dataid == 41477) {
			LOGGER.debug(" tecie voice quality report raw ");
			long length = bs.readUnsignedInt();
			event.getProtocolDetails().put("VQReportRaw",
					bs.readBytesAsHex((int) length));
		} else if (dataid == 40965) {
			LOGGER.debug(" tecie network info ");
			// TODO Have we use tekBitmask now !
			// TODO one variable using +
			if ((tekBitmask & 0x1) != 0) {
				event.getProtocolDetails().put("TekIENetworkInfoECGI",
						bs.readStringAsHex());
			}
			int nodeCount = (int) bs.readUnsignedInt();
			event.getProtocolDetails().put("TekIENetworkInfoNodeCount",
					nodeCount);

			for (int i = 0; i < nodeCount; i++) {
				if ((tekBitmask & 0x2) != 0)
					event.getProtocolDetails().put(
							"TekIENetworkInfoNodeIp-" + i + "-Address",
							bs.readStringAsHex());

				if ((tekBitmask & 0x4) != 0)
					event.getProtocolDetails().put(
							"TekIENetworkInfoNodeIp-" + i + "-Type",
							bs.readStringAsHex());

				if ((tekBitmask & 0x8) != 0)
					event.getProtocolDetails().put(
							"TekIENetworkInfoNodeIp-1-Name",
							bs.readStringAsHex());
			}
		} else if (dataid == 40966) {
			// TODO one variable using +
			LOGGER.debug(" tecie user tunnel ");
			int tunnelInfoCount = bs.readUnsignedShort();
			event.getProtocolDetails().put("tunnelInfoCount", tunnelInfoCount);

			for (int i = 0; i < tunnelInfoCount; i++) {

				if ((tekBitmask & 0x1) != 0) {
					event.getProtocolDetails().put(
							"tunnelInfoIP-" + i + "-Address",
							bs.readStringAsHex());
					event.getProtocolDetails().put(
							"tunnelInfo-" + i + "-Direction",
							bs.readUnsignedByte());
				}
				if ((tekBitmask & 0x2) != 0) {
					event.getProtocolDetails().put("tunnelInfo-" + i + "-Tied",
							bs.readUnsignedInt());
					event.getProtocolDetails().put(
							"tunnelInfo-" + i + "-TiedActive",
							bs.readUnsignedByte());
				}
				if ((tekBitmask & 0x4) != 0)
					event.getProtocolDetails().put(
							"tunnelInfo-" + i + "-NodeType",
							bs.readUnsignedShort());
				if ((tekBitmask & 0x8) != 0)
					event.getProtocolDetails()
							.put("tunnelInfo-" + i + "-NodeId",
									bs.readUnsignedInt());
			}
		} else if (dataid == 41478) {
			LOGGER.debug(" emergency service ");
			long bitmask = bs.readUnsignedInt();
			if ((bitmask & 1L) != 0L)
				event.getProtocolDetails().put("tunnelInfoIPAddress",
						bs.readStringAsHex());
		} else if (dataid == 41479) {
			LOGGER.debug(" no tunneled params ");
			long bitmask3 = bs.readUnsignedInt();
			if ((bitmask3 & 1L) != 0L) {
				event.getProtocolDetails().put(
						"noTunnelParamsDigestUsernameImsi",
						bs.readStringAsHex());
			}
			if ((bitmask3 & 0x2) != 0L) {
				String rlqEstAlg = bs.readStringAsHex();
				event.getProtocolDetails().put("noTunnelParamssipInstanceImei",
						bs.readStringAsHex());
			}
			if ((bitmask3 & 0x4) != 0L) {
				event.getProtocolDetails().put("noTunnelParamsSipInstanceSvn",
						bs.readStringAsHex());
			}
			if ((bitmask3 & 0x8) != 0L) {
				event.getProtocolDetails().put("noTunnelParamsPaniMacAddr",
						bs.readStringAsHex());
			}
			if ((bitmask3 & 0x10) != 0L) {
				event.getProtocolDetails().put("noTunnelParamsPlaniCellId",
						bs.readStringAsHex());
			}
		} else if (dataid == 41480) { // 0xA208
			LOGGER.debug(" P-ANI-Cell Id ");
			// TODO
			long bitmask3 = bs.readUnsignedInt();
			int count = bs.readUnsignedShort();

			if ((bitmask3 & 1L) != 0L) {

				if (!bpANICellIdList)
					bpANICellIdList = true;
				else
					pANICellIdList = pANICellIdList.concat("+");

				for (int i = 0; i < count; i++) {
					pANICellIdList = pANICellIdList
							.concat("" + bs.readString());
					if ((count - i) > 1) {
						pANICellIdList = pANICellIdList.concat("|");
					}
				}
			} else {
				if (!bpANICellIdList)
					bpANICellIdList = true;
				else
					pANICellIdList = pANICellIdList.concat("+");
			}
		} else if (dataid == 41481) {
			LOGGER.debug(" TransSatae SIP TekIE ");
			// long bitmask3=bs.readUnsignedInt(); // 22_1 as per shared feed
			long bitmask3 = tekBitmask;
			if ((bitmask3 & 0x1) != 0) {
				long bitmask = bs.readUnsignedShort();

				if ((bitmask & 1L) != 0L) {
					if (!btransactionStatInfoNewTransactionType)
						btransactionStatInfoNewTransactionType = true;
					else
						transactionStatInfoNewTransactionType = transactionStatInfoNewTransactionType
								.concat("+");

					transactionStatInfoNewTransactionType = transactionStatInfoNewTransactionType
							.concat("" + bs.readUnsignedInt());
				} else {
					if (!btransactionStatInfoNewTransactionType)
						btransactionStatInfoNewTransactionType = true;
					else
						transactionStatInfoNewTransactionType = transactionStatInfoNewTransactionType
								.concat("+");
				}
				if ((bitmask & 0x2) != 0L) {
					if (!btransactionStatInfoNewStartTime)
						btransactionStatInfoNewStartTime = true;
					else
						transactionStatInfoNewStartTime = transactionStatInfoNewStartTime
								.concat("+");
					transactionStatInfoNewStartTime = transactionStatInfoNewStartTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatInfoNewStartTime)
						btransactionStatInfoNewStartTime = true;
					else
						transactionStatInfoNewStartTime = transactionStatInfoNewStartTime
								.concat("+");
				}
				if ((bitmask & 0x4) != 0L) {
					if (!btransactionStatInfoNewEndTime)
						btransactionStatInfoNewEndTime = true;
					else
						transactionStatInfoNewEndTime = transactionStatInfoNewEndTime
								.concat("+");
					transactionStatInfoNewEndTime = transactionStatInfoNewEndTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatInfoNewEndTime)
						btransactionStatInfoNewEndTime = true;
					else
						transactionStatInfoNewEndTime = transactionStatInfoNewEndTime
								.concat("+");
				}
				if ((bitmask & 0x8) != 0L) {
					if (!btransactionStatInfoNewCauseCodes)
						btransactionStatInfoNewCauseCodes = true;
					else
						transactionStatInfoNewCauseCodes = transactionStatInfoNewCauseCodes
								.concat("+");

					int count = bs.readUnsignedByte();
					for (int i = 0; i < count; i++) {
						transactionStatInfoNewCauseCodes = transactionStatInfoNewCauseCodes
								.concat("" + bs.readUnsignedInt());
						if ((count - i) > 1)
							transactionStatInfoNewCauseCodes = transactionStatInfoNewCauseCodes
									.concat("|");
					}
				} else {
					if (!btransactionStatInfoNewCauseCodes)
						btransactionStatInfoNewCauseCodes = true;
					else
						transactionStatInfoNewCauseCodes = transactionStatInfoNewCauseCodes
								.concat("+");
				}
				if ((bitmask & 0x10) != 0L) {
					if (!btransactionStatBits)
						btransactionStatBits = true;
					else
						transactionStatBits = transactionStatBits.concat("+");
					transactionStatBits = transactionStatBits.concat(""
							+ bs.readUnsignedInt());
				} else {
					if (!btransactionStatBits)
						btransactionStatBits = true;
					else
						transactionStatBits = transactionStatBits.concat("+");
				}
				if ((bitmask & 0x20) != 0L) {
					if (!btransactionStatInfoNewTransactionDirection)
						btransactionStatInfoNewTransactionDirection = true;
					else
						transactionStatInfoNewTransactionDirection = transactionStatInfoNewTransactionDirection
								.concat("+");
					transactionStatInfoNewTransactionDirection = transactionStatInfoNewTransactionDirection
							.concat("" + bs.readUnsignedByte());
				} else {
					if (!btransactionStatInfoNewTransactionDirection)
						btransactionStatInfoNewTransactionDirection = true;
					else
						transactionStatInfoNewTransactionDirection = transactionStatInfoNewTransactionDirection
								.concat("+");
				}
				if ((bitmask & 0x40) != 0L) {
					if (!btransactionStatInfoNewProtocolId)
						btransactionStatInfoNewProtocolId = true;
					else
						transactionStatInfoNewProtocolId = transactionStatInfoNewProtocolId
								.concat("+");
					transactionStatInfoNewProtocolId = transactionStatInfoNewProtocolId
							.concat("" + bs.readUnsignedInt());
				} else {
					if (!btransactionStatInfoNewProtocolId)
						btransactionStatInfoNewProtocolId = true;
					else
						transactionStatInfoNewProtocolId = transactionStatInfoNewProtocolId
								.concat("+");
				}
				if ((bitmask & 0x80) != 0L) {
					if (!btransactionStatInfoNewSourceIp)
						btransactionStatInfoNewSourceIp = true;
					else
						transactionStatInfoNewSourceIp = transactionStatInfoNewSourceIp
								.concat("+");
					if (!btransactionStatInfoNewSourcePort)
						btransactionStatInfoNewSourcePort = true;
					else
						transactionStatInfoNewSourcePort = transactionStatInfoNewSourcePort
								.concat("+");

					int repetition = bs.readUnsignedByte();
					for (int i = 0; i < repetition; i++) {
						transactionStatInfoNewSourceIp = transactionStatInfoNewSourceIp
								.concat("" + bs.readStringAsHex());
						transactionStatInfoNewSourcePort = transactionStatInfoNewSourcePort
								.concat("" + bs.readUnsignedInt());
						if ((repetition - i) > 1) {
							transactionStatInfoNewSourceIp = transactionStatInfoNewSourceIp
									.concat("|");
							transactionStatInfoNewSourcePort = transactionStatInfoNewSourcePort
									.concat("|");
						}
					}
				} else {
					if (!btransactionStatInfoNewSourceIp)
						btransactionStatInfoNewSourceIp = true;
					else
						transactionStatInfoNewSourceIp = transactionStatInfoNewSourceIp
								.concat("+");

					if (!btransactionStatInfoNewSourcePort)
						btransactionStatInfoNewSourcePort = true;
					else
						transactionStatInfoNewSourcePort = transactionStatInfoNewSourcePort
								.concat("+");
				}
				if ((bitmask & 0x100) != 0L) {
					if (!btransactionStatInfoNewDestinationIp)
						btransactionStatInfoNewDestinationIp = true;
					else
						transactionStatInfoNewDestinationIp = transactionStatInfoNewDestinationIp
								.concat("+");

					if (!btransactionStatInfoNewDestinationPort)
						btransactionStatInfoNewDestinationPort = true;
					else
						transactionStatInfoNewDestinationPort = transactionStatInfoNewDestinationPort
								.concat("+");

					int repetition = bs.readUnsignedByte();
					for (int i = 0; i < repetition; i++) {
						transactionStatInfoNewDestinationIp = transactionStatInfoNewDestinationIp
								.concat("" + bs.readStringAsHex());
						transactionStatInfoNewDestinationPort = transactionStatInfoNewDestinationPort
								.concat("" + bs.readUnsignedInt());
						if ((repetition - i) > 1) {
							transactionStatInfoNewDestinationIp = transactionStatInfoNewDestinationIp
									.concat("|");
							transactionStatInfoNewDestinationPort = transactionStatInfoNewDestinationPort
									.concat("|");
						}
					}
				} else {
					if (!btransactionStatInfoNewDestinationIp)
						btransactionStatInfoNewDestinationIp = true;
					else
						transactionStatInfoNewDestinationIp = transactionStatInfoNewDestinationIp
								.concat("+");

					if (!btransactionStatInfoNewDestinationPort)
						btransactionStatInfoNewDestinationPort = true;
					else
						transactionStatInfoNewDestinationPort = transactionStatInfoNewDestinationPort
								.concat("+");
				}
				if ((bitmask & 0x200) != 0L) {
					if (!btransactionStatInfoNewOperationBits)
						btransactionStatInfoNewOperationBits = true;
					else
						transactionStatInfoNewOperationBits = transactionStatInfoNewOperationBits
								.concat("+");
					transactionStatInfoNewOperationBits = transactionStatInfoNewOperationBits
							.concat("" + bs.readUnsignedInt());
				} else {
					if (!btransactionStatInfoNewOperationBits)
						btransactionStatInfoNewOperationBits = true;
					else
						transactionStatInfoNewOperationBits = transactionStatInfoNewOperationBits
								.concat("+");
				}
				if ((bitmask & 0x1000) != 0L) {
					if (!btransactionStatInfoNewBitsExtention)
						btransactionStatInfoNewBitsExtention = true;
					else
						transactionStatInfoNewBitsExtention = transactionStatInfoNewBitsExtention
								.concat("+");
					transactionStatInfoNewBitsExtention = transactionStatInfoNewBitsExtention
							.concat("" + bs.readUnsignedInt());
				} else {
					if (!btransactionStatInfoNewBitsExtention)
						btransactionStatInfoNewBitsExtention = true;
					else
						transactionStatInfoNewBitsExtention = transactionStatInfoNewBitsExtention
								.concat("+");
				}
				if ((bitmask & 0x2000) != 0L) {
					if (!btransactionStatInfoNewVlanlds)
						btransactionStatInfoNewVlanlds = true;
					else
						transactionStatInfoNewVlanlds = transactionStatInfoNewVlanlds
								.concat("+");

					int count = bs.readUnsignedByte();
					for (int i = 0; i < count; i++) {
						transactionStatInfoNewVlanlds = transactionStatInfoNewVlanlds
								.concat("" + bs.readUnsignedInt());
						if ((count - i) > 1) {
							transactionStatInfoNewVlanlds = transactionStatInfoNewVlanlds
									.concat("|");
						}
					}
				} else {
					if (!btransactionStatInfoNewVlanlds)
						btransactionStatInfoNewVlanlds = true;
					else
						transactionStatInfoNewVlanlds = transactionStatInfoNewVlanlds
								.concat("+");
				}
			} else {
				if (!btransactionStatInfoNewTransactionType)
					btransactionStatInfoNewTransactionType = true;
				else
					transactionStatInfoNewTransactionType = transactionStatInfoNewTransactionType
							.concat("+");

				if (!btransactionStatInfoNewStartTime)
					btransactionStatInfoNewStartTime = true;
				else
					transactionStatInfoNewStartTime = transactionStatInfoNewStartTime
							.concat("+");

				if (!btransactionStatInfoNewEndTime)
					btransactionStatInfoNewEndTime = true;
				else
					transactionStatInfoNewEndTime = transactionStatInfoNewEndTime
							.concat("+");

				if (!btransactionStatInfoNewCauseCodes)
					btransactionStatInfoNewCauseCodes = true;
				else
					transactionStatInfoNewCauseCodes = transactionStatInfoNewCauseCodes
							.concat("+");

				if (!btransactionStatBits)
					btransactionStatBits = true;
				else
					transactionStatBits = transactionStatBits.concat("+");

				if (!btransactionStatInfoNewTransactionDirection)
					btransactionStatInfoNewTransactionDirection = true;
				else
					transactionStatInfoNewTransactionDirection = transactionStatInfoNewTransactionDirection
							.concat("+");

				if (!btransactionStatInfoNewProtocolId)
					btransactionStatInfoNewProtocolId = true;
				else
					transactionStatInfoNewProtocolId = transactionStatInfoNewProtocolId
							.concat("+");

				if (!btransactionStatInfoNewSourceIp)
					btransactionStatInfoNewSourceIp = true;
				else
					transactionStatInfoNewSourceIp = transactionStatInfoNewSourceIp
							.concat("+");

				if (!btransactionStatInfoNewSourcePort)
					btransactionStatInfoNewSourcePort = true;
				else
					transactionStatInfoNewSourcePort = transactionStatInfoNewSourcePort
							.concat("+");

				if (!btransactionStatInfoNewDestinationIp)
					btransactionStatInfoNewDestinationIp = true;
				else
					transactionStatInfoNewDestinationIp = transactionStatInfoNewDestinationIp
							.concat("+");

				if (!btransactionStatInfoNewDestinationPort)
					btransactionStatInfoNewDestinationPort = true;
				else
					transactionStatInfoNewDestinationPort = transactionStatInfoNewDestinationPort
							.concat("+");

				if (!btransactionStatInfoNewOperationBits)
					btransactionStatInfoNewOperationBits = true;
				else
					transactionStatInfoNewOperationBits = transactionStatInfoNewOperationBits
							.concat("+");

				if (!btransactionStatInfoNewBitsExtention)
					btransactionStatInfoNewBitsExtention = true;
				else
					transactionStatInfoNewBitsExtention = transactionStatInfoNewBitsExtention
							.concat("+");

				if (!btransactionStatInfoNewVlanlds)
					btransactionStatInfoNewVlanlds = true;
				else
					transactionStatInfoNewVlanlds = transactionStatInfoNewVlanlds
							.concat("+");
			}
			if ((bitmask3 & 0x2) != 0L) {
				LOGGER.debug(" Reson Headers ");
				long bitmask = bs.readUnsignedInt();

				if (!btransactionStatReasonHeaderDataList)
					btransactionStatReasonHeaderDataList = true;
				else
					transactionStatReasonHeaderDataList = transactionStatReasonHeaderDataList
							.concat("+");

				int count = 0;
				if ((bitmask & 1L) != 0L) {
					count = bs.readUnsignedShort();

					for (int i = 0; i < count; i++) {
						transactionStatReasonHeaderDataList = transactionStatReasonHeaderDataList
								.concat("" + bs.readString());
						if ((count - i) > 1) {
							transactionStatReasonHeaderDataList = transactionStatReasonHeaderDataList
									.concat("|");
						}
					}
				}
			} else {
				if (!btransactionStatReasonHeaderDataList)
					btransactionStatReasonHeaderDataList = true;
				else
					transactionStatReasonHeaderDataList = transactionStatReasonHeaderDataList
							.concat("+");
			}
			if (((bitmask3 & 0x4) != 0L)) {
				LOGGER.debug(" isup cause indicators ");
				long bitmask = bs.readUnsignedInt();

				if (!btransactionStatIsupCauseIndicatorsDataList)
					btransactionStatIsupCauseIndicatorsDataList = true;
				else
					transactionStatIsupCauseIndicatorsDataList = transactionStatIsupCauseIndicatorsDataList
							.concat("+");

				int count = 0;
				if ((bitmask & 1L) != 0L) {
					count = bs.readUnsignedShort();

					for (int i = 0; i < count; i++) {
						transactionStatIsupCauseIndicatorsDataList = transactionStatIsupCauseIndicatorsDataList
								.concat("" + bs.readString());
						if ((count - i) > 1) {
							transactionStatIsupCauseIndicatorsDataList = transactionStatIsupCauseIndicatorsDataList
									.concat("|");
						}
					}
				}
			} else {
				if (!btransactionStatIsupCauseIndicatorsDataList)
					btransactionStatIsupCauseIndicatorsDataList = true;
				else
					transactionStatIsupCauseIndicatorsDataList = transactionStatIsupCauseIndicatorsDataList
							.concat("+");
			}
			if ((bitmask3 & 0x8) != 0L) {
				LOGGER.debug(" pan cell id list ");
				long bitmask = bs.readUnsignedInt();

				if (!btransactionStatPaniCellIdDataList)
					btransactionStatPaniCellIdDataList = true;
				else
					transactionStatPaniCellIdDataList = transactionStatPaniCellIdDataList
							.concat("+");

				int count = 0;
				if ((bitmask & 1L) != 0L) {
					count = bs.readUnsignedShort();

					for (int i = 0; i < count; i++) {
						int position = bs.mark();
						transactionStatPaniCellIdDataListValues.add(
								transactionStatPaniCellIdDataListValues.size(),
								bs.readStringAsHex());
						bs.reset(position);
						transactionStatPaniCellIdDataList = transactionStatPaniCellIdDataList
								.concat("" + bs.readString());
						if ((count - i) > 1) {
							transactionStatPaniCellIdDataList = transactionStatPaniCellIdDataList
									.concat("|");
						}
					}
				}
			} else {
				if (!btransactionStatPaniCellIdDataList)
					btransactionStatPaniCellIdDataList = true;
				else
					transactionStatPaniCellIdDataList = transactionStatPaniCellIdDataList
							.concat("+");
			}
			if ((bitmask3 & 0x10) != 0L) {
				LOGGER.debug(" sip timer ");
				long bitmask = bs.readUnsignedInt();

				if ((bitmask & 1L) != 0L) {

					if (!btransactionStatSipTimerFirstRingingTime)
						btransactionStatSipTimerFirstRingingTime = true;
					else
						transactionStatSipTimerFirstRingingTime = transactionStatSipTimerFirstRingingTime
								.concat("+");
					transactionStatSipTimerFirstRingingTime = transactionStatSipTimerFirstRingingTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatSipTimerFirstRingingTime)
						btransactionStatSipTimerFirstRingingTime = true;
					else
						transactionStatSipTimerFirstRingingTime = transactionStatSipTimerFirstRingingTime
								.concat("+");
				}
				if ((bitmask & 0x2) != 0L) {

					if (!btransactionStatSipTimerLastRingingTime)
						btransactionStatSipTimerLastRingingTime = true;
					else
						transactionStatSipTimerLastRingingTime = transactionStatSipTimerLastRingingTime
								.concat("+");
					transactionStatSipTimerLastRingingTime = transactionStatSipTimerLastRingingTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatSipTimerLastRingingTime)
						btransactionStatSipTimerLastRingingTime = true;
					else
						transactionStatSipTimerLastRingingTime = transactionStatSipTimerLastRingingTime
								.concat("+");
				}
				if ((bitmask & 0x4) != 0L) {
					if (!btransactionStatSipTimerAnswerTime)
						btransactionStatSipTimerAnswerTime = true;
					else
						transactionStatSipTimerAnswerTime = transactionStatSipTimerAnswerTime
								.concat("+");
					transactionStatSipTimerAnswerTime = transactionStatSipTimerAnswerTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatSipTimerAnswerTime)
						btransactionStatSipTimerAnswerTime = true;
					else
						transactionStatSipTimerAnswerTime = transactionStatSipTimerAnswerTime
								.concat("+");
				}
				if ((bitmask & 0x8) != 0L) {
					if (!btransactionStatSipTimerAnswerConfirmTime)
						btransactionStatSipTimerAnswerConfirmTime = true;
					else
						transactionStatSipTimerAnswerConfirmTime = transactionStatSipTimerAnswerConfirmTime
								.concat("+");
					transactionStatSipTimerAnswerConfirmTime = transactionStatSipTimerAnswerConfirmTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatSipTimerAnswerConfirmTime)
						btransactionStatSipTimerAnswerConfirmTime = true;
					else
						transactionStatSipTimerAnswerConfirmTime = transactionStatSipTimerAnswerConfirmTime
								.concat("+");
				}
				if ((bitmask & 0x10) != 0L) {
					if (!btransactionStatSipTimerCancelTerminatedTime)
						btransactionStatSipTimerCancelTerminatedTime = true;
					else
						transactionStatSipTimerCancelTerminatedTime = transactionStatSipTimerCancelTerminatedTime
								.concat("+");
					transactionStatSipTimerCancelTerminatedTime = transactionStatSipTimerCancelTerminatedTime
							.concat("" + bs.readLong());
				} else {
					if (!btransactionStatSipTimerCancelTerminatedTime)
						btransactionStatSipTimerCancelTerminatedTime = true;
					else
						transactionStatSipTimerCancelTerminatedTime = transactionStatSipTimerCancelTerminatedTime
								.concat("+");
				}
			} else {
				if (!btransactionStatSipTimerFirstRingingTime)
					btransactionStatSipTimerFirstRingingTime = true;
				else
					transactionStatSipTimerFirstRingingTime = transactionStatSipTimerFirstRingingTime
							.concat("+");

				if (!btransactionStatSipTimerLastRingingTime)
					btransactionStatSipTimerLastRingingTime = true;
				else
					transactionStatSipTimerLastRingingTime = transactionStatSipTimerLastRingingTime
							.concat("+");

				if (!btransactionStatSipTimerAnswerTime)
					btransactionStatSipTimerAnswerTime = true;
				else
					transactionStatSipTimerAnswerTime = transactionStatSipTimerAnswerTime
							.concat("+");

				if (!btransactionStatSipTimerAnswerConfirmTime)
					btransactionStatSipTimerAnswerConfirmTime = true;
				else
					transactionStatSipTimerAnswerConfirmTime = transactionStatSipTimerAnswerConfirmTime
							.concat("+");

				if (!btransactionStatSipTimerCancelTerminatedTime)
					btransactionStatSipTimerCancelTerminatedTime = true;
				else
					transactionStatSipTimerCancelTerminatedTime = transactionStatSipTimerCancelTerminatedTime
							.concat("+");
			}
			if ((bitmask3 & 0x20) != 0L) {
				LOGGER.debug(" ptt info ");
				long bitmask = bs.readUnsignedInt();

				if ((bitmask & 1L) != 0L) {
					if (!btransactionStatPttinfoPocSessionType)
						btransactionStatPttinfoPocSessionType = true;
					else
						transactionStatPttinfoPocSessionType = transactionStatPttinfoPocSessionType
								.concat("+");
					transactionStatPttinfoPocSessionType = transactionStatPttinfoPocSessionType
							.concat("" + bs.readStringAsHex());
				} else {
					if (!btransactionStatPttinfoPocSessionType)
						btransactionStatPttinfoPocSessionType = true;
					else
						transactionStatPttinfoPocSessionType = transactionStatPttinfoPocSessionType
								.concat("+");
				}

				int counter = bs.readUnsignedShort();
				if ((bitmask & 0x2) != 0L) {

					if (!btransactionStatPttinfoFeatureTag1)
						btransactionStatPttinfoFeatureTag1 = true;
					else
						transactionStatPttinfoFeatureTag1 = transactionStatPttinfoFeatureTag1
								.concat("+");

					for (int i = 0; i < counter; i++) {
						transactionStatPttinfoFeatureTag1 = transactionStatPttinfoFeatureTag1
								.concat("" + bs.readStringAsHex());
						if ((counter - i) > 1) {
							transactionStatPttinfoFeatureTag1 = transactionStatPttinfoFeatureTag1
									.concat("|");
						}
					}
				} else {
					if (!btransactionStatPttinfoFeatureTag1)
						btransactionStatPttinfoFeatureTag1 = true;
					else
						transactionStatPttinfoFeatureTag1 = transactionStatPttinfoFeatureTag1
								.concat("+");
				}
			} else {
				if (!btransactionStatPttinfoPocSessionType)
					btransactionStatPttinfoPocSessionType = true;
				else
					transactionStatPttinfoPocSessionType = transactionStatPttinfoPocSessionType
							.concat("+");

				if (!btransactionStatPttinfoFeatureTag1)
					btransactionStatPttinfoFeatureTag1 = true;
				else
					transactionStatPttinfoFeatureTag1 = transactionStatPttinfoFeatureTag1
							.concat("+");
			}
		}
		//to remove , from transactionStatReasonHeaderDataList
		if(transactionStatReasonHeaderDataList.length()>0){
			transactionStatReasonHeaderDataList = transactionStatReasonHeaderDataList.replace(',',';');
		}
		sipdrTekInformationElement.setTransactionStatInfoNewTransactionType(transactionStatInfoNewTransactionType);
		sipdrTekInformationElement.setTransactionStatInfoNewStartTime(transactionStatInfoNewStartTime);
		sipdrTekInformationElement.setTransactionStatInfoNewEndTime(transactionStatInfoNewEndTime);
		sipdrTekInformationElement.setTransactionStatInfoNewCauseCodes(transactionStatInfoNewCauseCodes);
		sipdrTekInformationElement.setTransactionStatBits(transactionStatBits);
		sipdrTekInformationElement.setTransactionStatInfoNewTransactionDirection(transactionStatInfoNewTransactionDirection);
		sipdrTekInformationElement.setTransactionStatInfoNewProtocolId(transactionStatInfoNewProtocolId);
		sipdrTekInformationElement.setTransactionStatInfoNewSourceIp(transactionStatInfoNewSourceIp);
		sipdrTekInformationElement.setTransactionStatInfoNewSourcePort(transactionStatInfoNewSourcePort);
		sipdrTekInformationElement.setTransactionStatInfoNewDestinationIp(transactionStatInfoNewDestinationIp);
		sipdrTekInformationElement.setTransactionStatInfoNewDestinationPort(transactionStatInfoNewDestinationPort);
		sipdrTekInformationElement.setTransactionStatInfoNewOperationBits(transactionStatInfoNewOperationBits);
		sipdrTekInformationElement.setTransactionStatInfoNewBitsExtention(transactionStatInfoNewBitsExtention);
		sipdrTekInformationElement.setTransactionStatInfoNewVlanlds(transactionStatInfoNewVlanlds);
		// ReasonHeaders
		sipdrTekInformationElement.setTransactionStatReasonHeaderDataList(transactionStatReasonHeaderDataList);
		// isupCauseIndicators
		sipdrTekInformationElement.setTransactionStatIsupCauseIndicatorsDataList(transactionStatIsupCauseIndicatorsDataList);
		// panCellIdDataList
		sipdrTekInformationElement.setTransactionStatPaniCellIdDataList(transactionStatPaniCellIdDataList);
		// sip titransactionStatPaniCellIdDataList
		sipdrTekInformationElement.setTransactionStatSipTimerFirstRingingTime(transactionStatSipTimerFirstRingingTime);
		sipdrTekInformationElement.setTransactionStatSipTimerLastRingingTime(transactionStatSipTimerLastRingingTime);
		sipdrTekInformationElement.setTransactionStatSipTimerAnswerTime(transactionStatSipTimerAnswerTime);
		sipdrTekInformationElement.setTransactionStatSipTimerAnswerConfirmTime(transactionStatSipTimerAnswerConfirmTime);
		sipdrTekInformationElement.setTransactionStatSipTimerCancelTerminatedTime(transactionStatSipTimerCancelTerminatedTime);
		// pttinfo
		sipdrTekInformationElement.setTransactionStatPttinfoPocSessionType(transactionStatPttinfoPocSessionType);
		sipdrTekInformationElement.setTransactionStatPttinfoFeatureTag1(transactionStatPttinfoFeatureTag1);
		// A209 end
		// A208
		sipdrTekInformationElement.setpANICellIdList(pANICellIdList);
		// 29_1 end
		sipdrTekInformationElement.setBtransactionStatInfoNewTransactionType(btransactionStatInfoNewTransactionType);
		sipdrTekInformationElement.setBtransactionStatInfoNewStartTime(btransactionStatInfoNewStartTime);
		sipdrTekInformationElement.setBtransactionStatInfoNewEndTime(btransactionStatInfoNewEndTime);
		sipdrTekInformationElement.setBtransactionStatInfoNewCauseCodes(btransactionStatInfoNewCauseCodes);
		sipdrTekInformationElement.setBtransactionStatBits(btransactionStatBits);
		sipdrTekInformationElement.setBtransactionStatInfoNewTransactionDirection(btransactionStatInfoNewTransactionDirection);
		sipdrTekInformationElement.setBtransactionStatInfoNewProtocolId(btransactionStatInfoNewProtocolId);
		sipdrTekInformationElement.setBtransactionStatInfoNewSourceIp(btransactionStatInfoNewSourceIp);
		sipdrTekInformationElement.setBtransactionStatInfoNewSourcePort(btransactionStatInfoNewSourcePort);
		sipdrTekInformationElement.setBtransactionStatInfoNewDestinationIp(btransactionStatInfoNewDestinationIp);
		sipdrTekInformationElement.setBtransactionStatInfoNewDestinationPort(btransactionStatInfoNewDestinationPort);
		sipdrTekInformationElement.setBtransactionStatInfoNewOperationBits(btransactionStatInfoNewOperationBits);
		sipdrTekInformationElement.setBtransactionStatInfoNewBitsExtention(btransactionStatInfoNewBitsExtention);
		sipdrTekInformationElement.setBtransactionStatInfoNewVlanlds(btransactionStatInfoNewVlanlds);
		// ReasonsHeaders
		sipdrTekInformationElement.setBtransactionStatReasonHeaderDataList(btransactionStatReasonHeaderDataList);
		// isupCauseIndicators
		sipdrTekInformationElement.setBtransactionStatIsupCauseIndicatorsDataList(btransactionStatIsupCauseIndicatorsDataList);
		// panCellId
		sipdrTekInformationElement.setBtransactionStatPaniCellIdDataList(btransactionStatPaniCellIdDataList);
		// transactionStatSipTimer
		sipdrTekInformationElement.setBtransactionStatSipTimerFirstRingingTime(btransactionStatSipTimerFirstRingingTime);
		sipdrTekInformationElement.setBtransactionStatSipTimerLastRingingTime(btransactionStatSipTimerLastRingingTime);
		sipdrTekInformationElement.setBtransactionStatSipTimerAnswerTime(btransactionStatSipTimerAnswerTime);
		sipdrTekInformationElement.setBtransactionStatSipTimerAnswerConfirmTime(btransactionStatSipTimerAnswerConfirmTime);
		sipdrTekInformationElement.setBtransactionStatSipTimerCancelTerminatedTime(btransactionStatSipTimerCancelTerminatedTime);
		// pttinfo
		sipdrTekInformationElement.setBtransactionStatPttinfoPocSessionType(btransactionStatPttinfoPocSessionType);
		sipdrTekInformationElement.setBtransactionStatPttinfoFeatureTag1(btransactionStatPttinfoFeatureTag1);
		// A208
		sipdrTekInformationElement.setBpANICellIdList(bpANICellIdList);

		sipdrTekInformationElement.setTransactionStatPaniCellIdDataListValues(transactionStatPaniCellIdDataListValues);
		
	}

	private void readContent(int elementNum, ByteStream bs, ProtocolEvent event)
			throws IOException {
		for (int el = 0; el != elementNum; el++) {
			long elementmask = bs.readUnsignedInt(); // Bitmask value for all
														// elements in section
														// n. // 00 07 FF FE
			int elementtype = (int) ((elementmask & 0xE0000000) >> 29); // bit
																		// (32-30)
																		// indicate
																		// number
																		// of
																		// bytes
																		// with
																		// in
																		// parameters
																		// from
																		// n
																		// section.
			System.out.println("  elementtype {} "+elementtype);

			switch (elementtype) {
			case 0:
				parseWords(bs, elementmask, event);
				break;
			case 1:
				parseShorts(bs, elementmask, event);
				break;
			case 2:
				parseVariables(bs, elementmask, event);
				break;
			default:
				throw new IllegalStateException("Invalid section type "
						+ elementtype + ".");
			}
		}
	}

	private void parseWords(ByteStream bs, long mask, ProtocolEvent event) // All
																			// elements
																			// in
																			// section
																			// 1
																			// have
																			// same
																			// Bitmask
																			// ID
			throws IOException {
		LOGGER.debug(" parsing word part ");
		if ((mask & 1L) != 0L) {
			event.getProtocolDetails().put("callNumber", bs.readUnsignedInt());
		}
		if ((mask & 0x2) != 0L) {
			event.setEventStartTime(bs.readUnsignedInt());
		}
		if ((mask & 0x4) != 0L) {
			event.getProtocolDetails().put("startTimeUSec",
					bs.readUnsignedInt());
		}
		if ((mask & 0x8) != 0L) {
			event.setEventEndTime(bs.readUnsignedInt());
		}
		if ((mask & 0x10) != 0L) {
			event.getProtocolDetails().put("endTimeUSec", bs.readUnsignedInt());
		}
		if ((mask & 0x20) != 0L) {
			event.getProtocolDetails().put("ringingProcessTime",
					bs.readUnsignedInt());
		}
		if ((mask & 0x40) != 0L) {
			event.getProtocolDetails().put("ringingProcessMicroTime",
					bs.readUnsignedInt());
		}
		if ((mask & 0x80) != 0L) {
			event.getProtocolDetails().put("callAnsweredTime",
					bs.readUnsignedInt());
		}
		if ((mask & 0x100) != 0L) {
			event.getProtocolDetails().put("callAnsweredMicroTime",
					bs.readUnsignedInt());
		}
		if ((mask & 0x200) != 0L) {
			event.getProtocolDetails().put("callAnsweresConfirm",
					bs.readUnsignedInt());	
		}
		if ((mask & 0x400) != 0L) {
			event.getProtocolDetails().put("callAnsweresMicroConfirm",
					bs.readUnsignedInt());
		}
		if ((mask & 0x800) != 0L) {
			event.getProtocolDetails().put("callTerminalTime",
					bs.readUnsignedInt());
		}
		if ((mask & 0x1000) != 0L) {
			event.getProtocolDetails().put("callTerminalMicroTime",
					bs.readUnsignedInt());
		}
		if ((mask & 0x2000) != 0L) {
			event.getProtocolDetails().put("statusbits", bs.readUnsignedInt());
		}
		if ((mask & 0x4000) != 0L) {
			event.getProtocolDetails().put("timeoutbits", bs.readUnsignedInt());
		}
		if ((mask & 0x8000) != 0L) {
			event.getProtocolDetails().put("interfaceid", bs.readUnsignedInt());
		}
		if ((mask & 0x10000) != 0L) {
			event.getProtocolDetails().put("sourceIpAddress",
					bs.readUnsignedInt());
		}
		if ((mask & 0x20000) != 0L) {
			event.getProtocolDetails().put("destinationIpAddress",
					bs.readUnsignedInt());
		}

		if ((mask & 0x40000) != 0L) {
			event.getProtocolDetails().put("conditionIndicator",
					bs.readUnsignedInt());
		}

		if ((mask & 0x80000) != 0L) {
			event.getProtocolDetails().put("releaseDetectionTime",
					bs.readUnsignedInt());
		}

		if ((mask & 0x100000) != 0L) {
			event.getProtocolDetails().put("extCallNumberLow",
					bs.readUnsignedInt());
		}

		if ((mask & 0x200000) != 0L) {
			event.getProtocolDetails().put("extCallNumberHigh",
					bs.readUnsignedInt());
		}

		if ((mask & 0x400000) != 0L) {
			event.getProtocolDetails().put("bladeId", bs.readUnsignedInt());
		}

		if ((mask & 0x800000) != 0L) {
			event.getProtocolDetails().put("linkId", bs.readUnsignedInt());
		}

		if ((mask & 0x1000000) != 0L) {
			event.getProtocolDetails()
					.put("sourceNodeId", bs.readUnsignedInt());
		}

		if ((mask & 0x2000000) != 0L) {
			event.getProtocolDetails().put("destinationNodeId",
					bs.readUnsignedInt());
		}

		if ((mask & 0x4000000) != 0L) {
			event.getProtocolDetails().put("sessionStatusExt",
					bs.readUnsignedInt());
		}

		if ((mask & 0x8000000) != 0L) {
			event.getProtocolDetails().put("sessionStatus",
					bs.readUnsignedInt());
		}
	}

	private void parseShorts(ByteStream bs, long mask, ProtocolEvent event) // All
																			// elements
																			// in
																			// section
																			// 2
			throws IOException {
		LOGGER.debug(" parsing shorts part ");
		if ((mask & 1L) != 0L) {
			event.getProtocolDetails().put("equipmentId",
					bs.readUnsignedShort());
		}
		if ((mask & 0x2) != 0L) {
			event.getProtocolDetails().put("processorId",
					bs.readUnsignedShort());
		}
		if ((mask & 0x4) != 0L) {
			event.getProtocolDetails().put("appProtocol",
					bs.readUnsignedShort());
		}
		if ((mask & 0x8) != 0L) {
			event.getProtocolDetails().put("callType", bs.readUnsignedShort());
		}
		if ((mask & 0x10) != 0L) {
			event.getProtocolDetails().put("responseCode",
					bs.readUnsignedShort());
		}
		if ((mask & 0x20) != 0L) {
			event.getProtocolDetails().put("releaseCause",
					bs.readUnsignedShort());
		}
		if ((mask & 0x40) != 0L) {
			event.getProtocolDetails().put("releaseNode",
					bs.readUnsignedShort());
		}
		if ((mask & 0x80) != 0L) {
			event.getProtocolDetails().put("sourcePortNumber",
					bs.readUnsignedShort());
		}
		if ((mask & 0x100) != 0L) {
			event.getProtocolDetails().put("destinationPortNumber",
					bs.readUnsignedShort());
		}
		if ((mask & 0x200) != 0L) {
			event.getProtocolDetails().put("protocolInformation",
					bs.readUnsignedShort());
		}
		if ((mask & 0x400) != 0L) {
			event.getProtocolDetails().put("callTearDown",
					bs.readUnsignedShort());
		}

		if ((mask & 0x800) != 0L) {
			event.getProtocolDetails().put("sourceNodeTypeId",
					bs.readUnsignedShort());
		}

		if ((mask & 0x1000) != 0L) {
			event.getProtocolDetails().put("destinationNodeTypeId",
					bs.readUnsignedShort());
		}

		if ((mask & 0x2000) != 0L) {
			event.getProtocolDetails().put("interfaceTypeId",
					bs.readUnsignedShort());
		}

		if ((mask & 0x4000) != 0L) {
			event.getProtocolDetails().put("OICC", bs.readUnsignedShort());
		}

		if ((mask & 0x8000) != 0L) {
			event.getProtocolDetails().put("dataCastStatusBits",
					bs.readUnsignedShort());
		}

		if ((mask & 0x10000) != 0L) {
			event.getProtocolDetails()
					.put("tunnelType", bs.readUnsignedShort());
		}
		if ( versionId >=8 && (mask & 0x20000) != 0L) {
			event.getProtocolDetails().put("handoverDRType",
					bs.readUnsignedShort());
		}

		if ( versionId >=8 && (mask & 0x40000) != 0L) {
			event.getProtocolDetails()
					.put("handoverTimeoutIndicator", bs.readUnsignedShort());
		}
	}

	public void parseVariables(ByteStream bs, long mask, ProtocolEvent event)
			throws IOException {
		LOGGER.debug(" parsing variable  part ");
		if ((mask & 1L) != 0L) {

			int position1 = bs.mark();
			String fromURI = bs.readString();
			event.getProtocolDetails().put("fromUri", fromURI);

			if (((event.getProtocolDetails().get("destinationNodeTypeId") != null) && (int) event
					.getProtocolDetails().get("destinationNodeTypeId") == 16)
					&& ((event.getProtocolDetails().get("sourceNodeTypeId") != null) && (int) event
							.getProtocolDetails().get("sourceNodeTypeId") == 65535)) {
				bs.reset(position1);
				String hexString = bs.readStringAsHex();
				bs.reset(position1);
				int index = hexString.indexOf("40");
				hexString = hexString.substring(index + 2);
				int apnLength = hexString.length();
				int apnIndex = (apnLength / 2);
				int msisdnIndex = (index / 2);

				if (fromURI.startsWith("sip:+") ) {  
					//bs.skipBits(6);
					//String msisdn = bs.readString((msisdnIndex - 5));
					//					 
					String msisdn="";
					if(fromURI.contains(";")){
						msisdn = fromURI.substring(fromURI.indexOf("+")+1, fromURI.indexOf(";"));
						}
						else if(fromURI.contains("@")){
							msisdn = fromURI.substring(fromURI.indexOf("+")+1, fromURI.indexOf("@"));	
						}
						else{
							msisdn = fromURI.substring(fromURI.indexOf("+")+1);
						}
				
					//
					//bs.skipBits(1);
					//String apn = bs.readString(apnIndex);

					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
					//event.getProtocolDetails().put("apn", apn);
					//event.setServiceTarget(apn);
				} 
				// 1661 - Part 1
				else if (fromURI.startsWith("sip:01") ) { 
					String msisdn="";
					fromURI=fromURI.replaceFirst("sip:0", "sip:49");
					if(fromURI.contains(";")){
					msisdn = fromURI.substring(fromURI.indexOf(":")+1, fromURI.indexOf(";"));
					}
					else if(fromURI.contains("@")){
						msisdn = fromURI.substring(fromURI.indexOf(":")+1, fromURI.indexOf("@"));	
					}
					else{
						msisdn = fromURI.substring(fromURI.indexOf(":")+1);
					}
					
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
				}
				else if (fromURI.startsWith("tel:+") ) { 
					String msisdn="";
					if(fromURI.contains(";")){
						msisdn = fromURI.substring(fromURI.indexOf("+")+1, fromURI.indexOf(";"));
						}
						else if(fromURI.contains("@")){
							msisdn = fromURI.substring(fromURI.indexOf("+")+1, fromURI.indexOf("@"));	
						}
						else{
							msisdn = fromURI.substring(fromURI.indexOf("+")+1);
						}
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
				}
				else if (fromURI.startsWith("tel:00") ) {
					String msisdn="";
					if(fromURI.contains(";")){
						msisdn = fromURI.substring(fromURI.indexOf(":00")+3, fromURI.indexOf(";"));
						}
						else if(fromURI.contains("@")){
							msisdn = fromURI.substring(fromURI.indexOf(":00")+3, fromURI.indexOf("@"));	
						}
						else{
							msisdn = fromURI.substring(fromURI.indexOf(":00")+3);
						}
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
				}
				else if (fromURI.startsWith("tel:01") ) { 
					String msisdn ="";
					fromURI=fromURI.replaceFirst("tel:0", "tel:49");
					if(fromURI.contains(";")){
						msisdn = fromURI.substring(fromURI.indexOf(":")+1, fromURI.indexOf(";"));
						}
						else if(fromURI.contains("@")){
							msisdn = fromURI.substring(fromURI.indexOf(":")+1, fromURI.indexOf("@"));	
						}
						else{
							msisdn = fromURI.substring(fromURI.indexOf(":")+1);
						}
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
				}
				// 1661 - END
				else if (fromURI.startsWith("sip:00") ) {					
					//
					String msisdn="";
					if(fromURI.contains(";")){
						msisdn = fromURI.substring(fromURI.indexOf(":00")+3, fromURI.indexOf(";"));
						}
						else if(fromURI.contains("@")){
							msisdn = fromURI.substring(fromURI.indexOf(":00")+3, fromURI.indexOf("@"));	
						}
						else{
							msisdn = fromURI.substring(fromURI.indexOf(":00")+3);
						}
				
					//
					//bs.skipBits(7);
					//String msisdn = bs.readString((msisdnIndex - 6));
					//bs.skipBits(1);
					//String apn = bs.readString(apnIndex);

					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
					//event.getProtocolDetails().put("apn", apn);
					//event.setServiceTarget(apn);
				} else {
					event.getProtocolDetails().put("msisdn", "");
					event.setServiceId("");
					event.getProtocolDetails().put("apn", "");
					event.setServiceTarget("");
				}
				// bs.reset(position1);
				// bs.readString();
			} else if (((event.getProtocolDetails().get("sourceNodeTypeId") != null) && ((int) event
					.getProtocolDetails().get("sourceNodeTypeId") == 16))
					&& ((event.getProtocolDetails()
							.get("destinationNodeTypeId") != null) && ((int) event
							.getProtocolDetails().get("destinationNodeTypeId") == 65535))) {

				int position2 = bs.mark();
				String toURI = bs.readString();
				bs.reset(position2);

				String hexString = bs.readStringAsHex();
				bs.reset(position2);
				int index = hexString.indexOf("40");
				hexString = hexString.substring(index + 2);
				int apnLength = hexString.length();
				int apnIndex = (apnLength / 2);
				int msisdnIndex = (index / 2);

				if (toURI.startsWith("sip:+") ) {
					//bs.skipBits(6);
					//String msisdn = bs.readString((msisdnIndex - 5));
					//

					   String msisdn="";
						if(toURI.contains(";")){
							msisdn = toURI.substring(toURI.indexOf("+")+1, toURI.indexOf(";"));
						}
						else if(toURI.contains("@")){
							msisdn = toURI.substring(toURI.indexOf("+")+1, toURI.indexOf("@"));	
						}
						else{
								msisdn = toURI.substring(toURI.indexOf("+")+1);
						}
					   
				   
					//
					//bs.skipBits(1);
					//String apn = bs.readString(apnIndex);

					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
					//event.getProtocolDetails().put("apn", apn);
					//event.setServiceTarget(apn);
				} 
				// 1661 - Part 2
			   else if (toURI.startsWith("sip:01") ) { 
				    String msisdn ="";
					toURI=toURI.replaceFirst("sip:0", "sip:49");
					if(toURI.contains(";")){
						msisdn = toURI.substring(toURI.indexOf(":")+1, toURI.indexOf(";"));
					}
					else if(toURI.contains("@")){
						msisdn = toURI.substring(toURI.indexOf(":")+1, toURI.indexOf("@"));	
					}
					else{
						msisdn = toURI.substring(toURI.indexOf(":")+1);
						}
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
			   }
			   else if (toURI.startsWith("tel:+") ) {
				   String msisdn="";
					if(toURI.contains(";")){
						msisdn = toURI.substring(toURI.indexOf("+")+1, toURI.indexOf(";"));
					}
					else if(toURI.contains("@")){
						msisdn = toURI.substring(toURI.indexOf("+")+1, toURI.indexOf("@"));	
					}
					else{
							msisdn = toURI.substring(toURI.indexOf("+")+1);
					}
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);				   
			   }
			   else if (toURI.startsWith("tel:00") ) {
					String msisdn="";
					if(toURI.contains(";")){
						msisdn = toURI.substring(toURI.indexOf(":00")+3, toURI.indexOf(";"));
					}
					else if(toURI.contains("@")){
						msisdn = toURI.substring(toURI.indexOf(":00")+3, toURI.indexOf("@"));	
					}
					else{
						msisdn = toURI.substring(toURI.indexOf(":00")+3);
					}
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
				}
			   else if (toURI.startsWith("tel:01") ) { 
				   String msisdn ="";
					toURI=toURI.replaceFirst("tel:0", "tel:49");
					if(toURI.contains(";")){
						msisdn = toURI.substring(toURI.indexOf(":")+1, toURI.indexOf(";"));
					}
					else if(toURI.contains("@")){
						msisdn = toURI.substring(toURI.indexOf(":")+1, toURI.indexOf("@"));	
					}
					else{
						msisdn = toURI.substring(toURI.indexOf(":")+1);
					}  
					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
			   }
				// END Part 2
				else if (toURI.startsWith("sip:00") ) {
					//

					String msisdn="";
					if(toURI.contains(";")){
						msisdn = toURI.substring(toURI.indexOf(":00")+3, toURI.indexOf(";"));
					}
					else if(toURI.contains("@")){
						msisdn = toURI.substring(toURI.indexOf(":00")+3, toURI.indexOf("@"));	
					}
					else{
						msisdn = toURI.substring(toURI.indexOf(":00")+3);
					}
				
					//
					//bs.skipBits(7);
					//String msisdn = bs.readString((msisdnIndex - 6));
					//bs.skipBits(1);
					//String apn = bs.readString(apnIndex);

					event.getProtocolDetails().put("msisdn", msisdn);
					event.setServiceId(msisdn);
					//event.getProtocolDetails().put("apn", apn);
					//event.setServiceTarget(apn);
				} else {
					event.getProtocolDetails().put("msisdn", "");
					event.setServiceId("");
					event.getProtocolDetails().put("apn", "");
					event.setServiceTarget("");
				}
				// bs.reset(position2);
				// bs.readString();
			} else {
				event.getProtocolDetails().put("msisdn", "");
				event.setServiceId("");
				event.getProtocolDetails().put("apn", "");
				event.setServiceTarget("");
			}
			bs.reset(position1);
			bs.readString();
		}
		if ((mask & 0x2) != 0L) {
			// String toURI = bs.readStringAsHex();
			String toURI = bs.readString();
			event.getProtocolDetails().put("toUri", toURI);
		}
		if ((mask & 0x4) != 0L) {
			String callId = bs.readString();
			event.getProtocolDetails().put("callId", callId);
		}
		if ((mask & 0x8) != 0L) {
			event.getProtocolDetails().put("calledAddress",
					bs.readStringAsHex());
		}
		if ((mask & 0x10) != 0L) {
			event.getProtocolDetails().put("dialedAddress",
					bs.readStringAsHex());
		}
		if ((mask & 0x20) != 0L) {
			event.getProtocolDetails().put("callingAddress",
					bs.readStringAsHex());
		}
		if ((mask & 0x40) != 0L) {
			event.getProtocolDetails().put("callingAssertedAddress",
					bs.readStringAsHex());
		}
		if ((mask & 0x80) != 0L) {
			event.getProtocolDetails().put("sourceIPv6", bs.readStringAsHex());
		}
		if ((mask & 0x100) != 0L) {
			event.getProtocolDetails().put("destinationIPv6",
					bs.readStringAsHex());
		}
		if ((mask & 0x200) != 0L) {
			String msisdn = bs.readString();
			event.getProtocolDetails().put("msisdn", msisdn);
			event.setServiceId(msisdn);
		}
		if ((mask & 0x400) != 0L) {
			// event.getProtocolDetails().put("imsi", bs.readStringAsHex());
			event.getProtocolDetails().put("imsi", bs.readString());
		}
		if ((mask & 0x800) != 0L) {
			event.getProtocolDetails().put("terminalIP", bs.readStringAsHex());
		}
		if ((mask & 0x1000) != 0L) {
			event.getProtocolDetails().put("msip", bs.readStringAsHex());
		}
		if ((mask & 0x2000) != 0L) {
			String apn = bs.readString();
			event.getProtocolDetails().put("apn", apn);
			event.setServiceTarget(apn);
		}
		if ((mask & 0x4000) != 0L) {
			event.getProtocolDetails().put("imei", bs.readStringAsHex());
		}
		if ((mask & 0x8000) != 0L) {
			event.getProtocolDetails().put("imeisv", bs.readStringAsHex());
		}
		if ((mask & 0x20000) != 0L) {
			event.getProtocolDetails().put("pgwIP", bs.readStringAsHex());
		}
		if ((mask & 0x40000) != 0L) {
			event.getProtocolDetails().put("firstEcgi", bs.readStringAsHex());
		}
		if ((mask & 0x80000) != 0L) {
			event.getProtocolDetails().put("lastEcgi", bs.readStringAsHex());
		}
		if ((mask & 0x100000) != 0L) {
			event.getProtocolDetails().put("PCSCFipAddress",
					bs.readStringAsHex());
		}
		if ((mask & 0x200000) != 0L) {
			event.getProtocolDetails().put("imsiCalling", bs.readStringAsHex());
		}
		if ((mask & 0x400000) != 0L) {
			event.getProtocolDetails().put("imsiCalled", bs.readStringAsHex());
		}
		if ((mask & 0x800000) != 0L) {
			event.getProtocolDetails().put("requestedCompressedQOS",
					bs.readStringAsHex());
		}
		if ((mask & 0x1000000) != 0L) {
			event.getProtocolDetails().put("negociatedCompressedQOS",
					bs.readStringAsHex());
		}
		if ( versionId >=8 && (mask & 0x2000000) != 0L) {//new
			event.getProtocolDetails().put("FirstP-ANI",
					bs.readStringAsHex());
		}
		if ( versionId >=8 && (mask & 0x4000000) != 0L) {//new
			event.getProtocolDetails().put("LatestP-ANI",
					bs.readStringAsHex());
		}
		// Padding
		// TODO Verify once
	}
	
	public void setSipdrTekInformationElementDeafaultValues(SipdrTekInformationElement sipdrTekInformationElement){
		sipdrTekInformationElement.setTransactionStatInfoNewTransactionType("");
		sipdrTekInformationElement.setTransactionStatInfoNewStartTime("");
		sipdrTekInformationElement.setTransactionStatInfoNewEndTime("");
		sipdrTekInformationElement.setTransactionStatInfoNewCauseCodes("");
		sipdrTekInformationElement.setTransactionStatBits("");
		sipdrTekInformationElement.setTransactionStatInfoNewTransactionDirection("");
		sipdrTekInformationElement.setTransactionStatInfoNewProtocolId("");
		sipdrTekInformationElement.setTransactionStatInfoNewSourceIp("");
		sipdrTekInformationElement.setTransactionStatInfoNewSourcePort("");
		sipdrTekInformationElement.setTransactionStatInfoNewDestinationIp("");
		sipdrTekInformationElement.setTransactionStatInfoNewDestinationPort("");
		sipdrTekInformationElement.setTransactionStatInfoNewOperationBits("");
		sipdrTekInformationElement.setTransactionStatInfoNewBitsExtention("");
		sipdrTekInformationElement.setTransactionStatInfoNewVlanlds("");
		// ReasonHeaders
		sipdrTekInformationElement.setTransactionStatReasonHeaderDataList("");
		// isupCauseIndicators
		sipdrTekInformationElement.setTransactionStatIsupCauseIndicatorsDataList("");
		// panCellIdDataList
		sipdrTekInformationElement.setTransactionStatPaniCellIdDataList("");
		// sip titransactionStatPaniCellIdDataList
		sipdrTekInformationElement.setTransactionStatSipTimerFirstRingingTime("");
		sipdrTekInformationElement.setTransactionStatSipTimerLastRingingTime("");
		sipdrTekInformationElement.setTransactionStatSipTimerAnswerTime("");
		sipdrTekInformationElement.setTransactionStatSipTimerAnswerConfirmTime("");
		sipdrTekInformationElement.setTransactionStatSipTimerCancelTerminatedTime("");
		// pttinfo
		sipdrTekInformationElement.setTransactionStatPttinfoPocSessionType("");
		sipdrTekInformationElement.setTransactionStatPttinfoFeatureTag1("");
		// A209 end
		// A208
		sipdrTekInformationElement.setpANICellIdList("");
		// 29_1 end
		sipdrTekInformationElement.setBtransactionStatInfoNewTransactionType(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewStartTime(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewEndTime(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewCauseCodes(false);
		sipdrTekInformationElement.setBtransactionStatBits(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewTransactionDirection(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewProtocolId(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewSourceIp(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewSourcePort(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewDestinationIp(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewDestinationPort(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewOperationBits(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewBitsExtention(false);
		sipdrTekInformationElement.setBtransactionStatInfoNewVlanlds(false);
		// ReasonsHeaders
		sipdrTekInformationElement.setBtransactionStatReasonHeaderDataList(false);
		// isupCauseIndicators
		sipdrTekInformationElement.setBtransactionStatIsupCauseIndicatorsDataList(false);
		// panCellId
		sipdrTekInformationElement.setBtransactionStatPaniCellIdDataList(false);
		// transactionStatSipTimer
		sipdrTekInformationElement.setBtransactionStatSipTimerFirstRingingTime(false);
		sipdrTekInformationElement.setBtransactionStatSipTimerLastRingingTime(false);
		sipdrTekInformationElement.setBtransactionStatSipTimerAnswerTime(false);
		sipdrTekInformationElement.setBtransactionStatSipTimerAnswerConfirmTime(false);
		sipdrTekInformationElement.setBtransactionStatSipTimerCancelTerminatedTime(false);
		// pttinfo
		sipdrTekInformationElement.setBtransactionStatPttinfoPocSessionType(false);
		sipdrTekInformationElement.setBtransactionStatPttinfoFeatureTag1(false);
		// A208
		sipdrTekInformationElement.setBpANICellIdList(false);

		sipdrTekInformationElement.setTransactionStatPaniCellIdDataListValues(new ArrayList());
	}
}

