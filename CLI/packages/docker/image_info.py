import json 

Image_Info = {}

def gen_image_info(image_config):

    try:
        Image_Info['Architecture'] = image_config['architecture']
        history = image_config.get('history')
        layers = [] 
        for h in history:
            l = h['created_by']
            l = l.split("/bin/sh -c #(nop) ")[1].strip()
            layers.append(l)
        
        Image_Info['Layers'] = layers
        Image_Info['No_of_Layers'] = len(layers)
    except:
        pass
    
    # print(json.dumps(Image_Info, indent=4))

    return Image_Info