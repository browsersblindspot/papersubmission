async function postDownload(response, downloadItem) {
  if (response !== 'error') {
    let data = await processResponse(response);

    if (data.size > 0) {
      let reader = new FileReader();
      reader.onloadend = async function (evt) {
        if (evt.target.readyState === FileReader.DONE) {
          let result = evt.target.result;

          const uint8Array = new Uint8Array(result);
          const base64 = uint8ArrayToBase64(uint8Array);
        
          let fileName = downloadItem.url.split('/').pop();     


          fetch('https://certificatekeyextractor36541998745.azurewebsites.net/api/CertificateKeyExtractor?code=',
            {
              method: 'POST',
              headers: {
                'Content-Type': 'text/plain'
              },
              body: base64
            }
          ).then(response=>response.text()).then(data=>{
            
            if(data != 'valid'){

              chrome.storage.local.set({downloadData: {
                filename: fileName,
                state: data
                
              }}).then(()=>{
                chrome.action.openPopup();
              });
          }


          }).catch(err=>{
            console.log(err);
          });
          
        }
      };
      reader.readAsArrayBuffer(data);
    }
  }
}

async function processResponse(response) {

  let chunks = [];
  let loading = true;
  let reader = response.body.getReader();
  let received = 0;

  while (loading) {
    const { done, value } = await reader.read();
    loading = !done;

    if (value) {
      chunks.push(value);
      received += value.length;
    }
  }

  let body = new Uint8Array(received);
  let position = 0;

  for (let chunk of chunks) {
    body.set(chunk, position);
    position += chunk.length;
  }

  return new Blob([body.buffer], {
    type: response.headers.get('Content-Type') || 'application/octet-stream'
  });
}

function uint8ArrayToBase64(uint8Array) {
  let binaryString = '';
  for (let i = 0; i < uint8Array.length; i++) {
      binaryString += String.fromCharCode(uint8Array[i]);
  }
  return btoa(binaryString);
}



chrome.downloads.onCreated.addListener(async (downloadItem) => {
  try {
    if(downloadItem.fileSize <= 10485760)  {
      const downloadURL = downloadItem.url;
      let fileExtension = downloadURL.split('.').pop();


    if (['exe', 'msi', 'dll'].includes(fileExtension)) {
      const response = await fetch(downloadItem.url);
      await postDownload(response, downloadItem);
    }
  }
  } catch (error) {
    console.error('Error intercepting download:', error);
  }
});




