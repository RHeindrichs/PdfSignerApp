package pdfsigner;

import org.bouncycastle.cms.CMSTypedData;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.cms.CMSObjectIdentifiers;

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

public class InputStreamTypedData implements CMSTypedData {

    private final InputStream input;

    public InputStreamTypedData(InputStream input) {
        this.input = input;
    }

    @Override
    public Object getContent() {
        return input;
    }

    @Override
    public void write(OutputStream out) throws IOException {
        byte[] buffer = new byte[8192];
        int read;
        while ((read = input.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        input.close();
    }

    @Override
    public ASN1ObjectIdentifier getContentType() {
        return CMSObjectIdentifiers.data;
    }
}
