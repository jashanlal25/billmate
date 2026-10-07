package com.billmate.nativeapp;

import java.io.IOException;
import org.junit.Test;
import static org.junit.Assert.assertThrows;

public class InvoiceImageShareTest {
    private final byte[] jpeg = new byte[]{(byte)255,(byte)216,(byte)255,0,(byte)255,(byte)217};

    @Test public void acceptsGeneratedJpegAndPageBatch() throws Exception {
        InvoiceImageShare.validateImage("SSD-0034.jpg", "image/jpeg", jpeg);
        InvoiceImageShare.validateTotal(4, jpeg.length * 4);
    }
    @Test public void rejectsWrongExtensionOrMime() {
        assertThrows(IOException.class, () -> InvoiceImageShare.validateImage("bill.pdf", "image/jpeg", jpeg));
        assertThrows(IOException.class, () -> InvoiceImageShare.validateImage("bill.jpg", "application/pdf", jpeg));
    }
    @Test public void rejectsEmptyCorruptAndTruncatedBytes() {
        assertThrows(IOException.class, () -> InvoiceImageShare.validateImage("bill.jpg", "image/jpeg", new byte[0]));
        assertThrows(IOException.class, () -> InvoiceImageShare.validateImage("bill.jpg", "image/jpeg", new byte[]{1,2,3,4}));
        assertThrows(IOException.class, () -> InvoiceImageShare.validateImage("bill.jpg", "image/jpeg", new byte[]{(byte)255,(byte)216,(byte)255,0}));
    }
    @Test public void enforcesWholeBatchLimits() throws Exception {
        InvoiceImageShare.validateTotal(50, InvoiceImageShare.MAX_TOTAL_BYTES);
        assertThrows(IOException.class, () -> InvoiceImageShare.validateTotal(0, 0));
        assertThrows(IOException.class, () -> InvoiceImageShare.validateTotal(51, 0));
        assertThrows(IOException.class, () -> InvoiceImageShare.validateTotal(2, InvoiceImageShare.MAX_TOTAL_BYTES + 1));
    }
}
