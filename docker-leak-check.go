package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"runtime"

	"github.com/Microsoft/hcsshim"
)

type imageType struct {
	RootFS *rootFS `json:"rootfs,omitempty"`
	OS     string  `json:"os,omitempty"`
}

type rootFS struct {
	Type    string   `json:"type"`
	DiffIDs []string `json:"diff_ids,omitempty"`
}

type layerDBItem struct {
	ID      string
	diff    string
	cacheID string
	visited bool
}

type rawLayerType struct {
	ID      string
	visited bool
}

func folderexists(path string) bool {
	_, err := os.Stat(path)
	if err == nil {
		return true
	}
	if os.IsNotExist(err) {
		return false
	}
	return true
}

func main() {
	var folder string
	defaultFolder := `C:\ProgramData\docker`
	graphDriver := "windowsfilter"
	if runtime.GOOS != "windows" {
		defaultFolder = `/var/lib/docker`
		graphDriver = "overlay2"
	}
	var remove bool
	flag.StringVar(&folder, "folder", "", "Root of the Docker runtime (default \""+defaultFolder+"\")")
	flag.BoolVar(&remove, "remove", false, "Remove unreferenced layers")
	flag.Parse()
	if folder == "" {
		folder = defaultFolder
	}
	if !folderexists(folder) {
		fmt.Println("Error: folder does not exist")
		os.Exit(-1)
	}

	imageDBFolder := filepath.Join(folder, "image", graphDriver, "imagedb", "content", "sha256")
	if !folderexists(imageDBFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", imageDBFolder)
		os.Exit(-1)
	}

	layerDBFolder := filepath.Join(folder, "image", graphDriver, "layerdb", "sha256")
	if !folderexists(layerDBFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", layerDBFolder)
		os.Exit(-1)
	}
	rawLayerFolder := filepath.Join(folder, graphDriver)
	if !folderexists(rawLayerFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", rawLayerFolder)
		os.Exit(-1)
	}
	containerFolder := filepath.Join(folder, "containers")
	if !folderexists(containerFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", containerFolder)
		os.Exit(-1)
	}

	unreferencedLayers, unreferencedRawLayers, err := verifyImagesAndLayers(rawLayerFolder, layerDBFolder, imageDBFolder, containerFolder)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	if len(unreferencedLayers) != 0 || len(unreferencedRawLayers) != 0 {
		for _, layer := range unreferencedLayers {
			if remove {
				fmt.Println("Info: Unreferenced layer in layerDB: ", layer, " removing...")
				err = removeDiskLayer(folder+"\\image\\windowsfilter\\layerdb\\sha256", layer)
				if err != nil {
					fmt.Println(err)
				}
			} else {
				fmt.Println("Error: Unreferenced layer in layerDB: ", layer)
			}
		}

		for _, layer := range unreferencedRawLayers {
			if graphDriver == "overlay2" && layer == "l" {
				continue
			}
			fmt.Println("Error: Unreferenced layer in "+graphDriver+": ", layer)
			if remove {
				fmt.Println("Info: Unreferenced layer in windowsfilter: ", layer, " removing...")
				err = removeDiskLayer(folder+"\\windowsfilter", layer)
				if err != nil {
					fmt.Println(err)
				}
			} else {
				fmt.Println("Error: Unreferenced layer in windowsfilter: ", layer)
			}
		}
		os.Exit(-1)
	}
	fmt.Println("No errors found")
}

func createRawLayerMap(rawLayerFolder string) (map[string]*rawLayerType, error) {
	files, err := ioutil.ReadDir(rawLayerFolder)
	if err != nil {
		return nil, fmt.Errorf("Error: failed to read files in %s: %v", rawLayerFolder, err)
	}
	var rawLayerMap = make(map[string]*rawLayerType)
	for _, f := range files {
		if f.IsDir() {
			rawLayer := &rawLayerType{}
			rawLayer.ID = f.Name()
			rawLayerMap[rawLayer.ID] = rawLayer
		}
	}
	return rawLayerMap, nil
}

func populateLayerDBMap(layerDBFolder string) (map[string]*layerDBItem, error) {
	// enumerate the existing layers in the LayerDB
	files, err := ioutil.ReadDir(layerDBFolder)
	if err != nil {
		return nil, fmt.Errorf("Error: failed to read files in %s: %v", layerDBFolder, err)
	}
	var layerMap = make(map[string]*layerDBItem)
	for _, f := range files {
		if f.IsDir() {
			layer := &layerDBItem{}
			layer.ID = f.Name()

			diffFile := filepath.Join(layerDBFolder, f.Name(), "diff")
			dat, err := ioutil.ReadFile(diffFile)
			if err != nil {
				return nil, fmt.Errorf("Error: failed to read file %s: %v", diffFile, err)
			}
			layer.diff = string(dat)

			cacheIDFile := filepath.Join(layerDBFolder, f.Name(), "cache-id")
			dat, err = ioutil.ReadFile(cacheIDFile)
			if err != nil {
				return nil, fmt.Errorf("Error: failed to read file %s: %v", cacheIDFile, err)
			}
			layer.cacheID = string(dat)

			layerMap[layer.diff] = layer
		}
	}
	return layerMap, nil
}

func verifyLayersOfImage(imagePath string, layerMap map[string]*layerDBItem, rawLayerMap map[string]*rawLayerType) error {
	dat, err := ioutil.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("Error: failed to read file %s: %v", imagePath, err)
	}
	image := &imageType{}
	if err := json.Unmarshal(dat, image); err != nil {
		return fmt.Errorf("Error: failed to read JSON contents of %s: %v", imagePath, err)
	}

	if runtime.GOOS == "windows" && image.OS == "linux" {
		fmt.Printf("WARN: Skipping linux (lcow) %s\n", imagePath)
		return nil
	}

	for _, diff := range image.RootFS.DiffIDs {
		layer := layerMap[diff]
		if layer == nil {
			return fmt.Errorf("Error: expected layer with diff %s", diff)
		}
		if rawLayerMap[layer.cacheID] == nil {
			return fmt.Errorf("Error: expected on-disk layer %s\n", layer.cacheID)
		}
		rawLayerMap[layer.cacheID].visited = true
		layer.visited = true
	}
	return nil
}

func verifyImages(imageDBFolder string, layerMap map[string]*layerDBItem, rawLayerMap map[string]*rawLayerType) error {
	files, err := ioutil.ReadDir(imageDBFolder)
	if err != nil {
		return fmt.Errorf("Error: failed to read files in %s: %v", imageDBFolder, err)
	}
	for _, f := range files {
		if !f.IsDir() {
			imagePath := filepath.Join(imageDBFolder, f.Name())
			err := verifyLayersOfImage(imagePath, layerMap, rawLayerMap)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func visitContainerLayers(containerFolder string, rawLayerMap map[string]*rawLayerType) error {
	files, err := ioutil.ReadDir(containerFolder)
	if err != nil {
		return fmt.Errorf("Error: failed to read files in %s: %v", containerFolder, err)
	}
	for _, f := range files {
		if f.IsDir() {
			layer := rawLayerMap[f.Name()]
			if layer != nil {
				layer.visited = true
			}
		}
	}
	return nil
}

func verifyImagesAndLayers(rawLayerFolder, layerDBFolder, imageDBFolder, containerFolder string) ([]string, []string, error) {
	rawLayerMap, err := createRawLayerMap(rawLayerFolder)
	if err != nil {
		return nil, nil, err
	}

	layerMap, err := populateLayerDBMap(layerDBFolder)
	if err != nil {
		return nil, nil, err
	}

	err = verifyImages(imageDBFolder, layerMap, rawLayerMap)
	if err != nil {
		return nil, nil, err
	}

	err = visitContainerLayers(containerFolder, rawLayerMap)
	if err != nil {
		return nil, nil, err
	}

	var unreferencedLayers []string
	for _, layer := range layerMap {
		if layer.visited == false {
			unreferencedLayers = append(unreferencedLayers, layer.ID)
		}
	}

	var unreferencedRawLayers []string
	for _, rawLayer := range rawLayerMap {
		if rawLayer.visited == false {
			unreferencedRawLayers = append(unreferencedRawLayers, rawLayer.ID)
		}
	}
	return unreferencedLayers, unreferencedRawLayers, nil
}

func removeDiskLayer(location, foldername string) error {
	info := hcsshim.DriverInfo{
		HomeDir: location,
		Flavour: 0,
	}
	return hcsshim.DestroyLayer(info, foldername)
}
