//go:build windows

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Reverse lookup of image sha sums to names. For logging purposes.
var imageNameDB = make(map[shaSum]string)

// Map of layers to image names. Unfortunately, Go doesn't have sets, hence we must use a map for the values.
var layerImageDB = make(map[shaSum]map[string]struct{})

type shaSum string

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

func folderExists(path string) bool {
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
	var remove bool
	var verbose bool
	flag.StringVar(&folder, "folder", "", "Root of the Docker runtime (default \"C:\\ProgramData\\docker\")")
	flag.BoolVar(&remove, "remove", false, "Remove unreferenced layers")
	flag.BoolVar(&verbose, "verbose", false, "Display extra info on valid layers")
	flag.Parse()
	if folder == "" {
		folder = `C:\programdata\docker`
	}
	if !folderExists(folder) {
		fmt.Println("Error: folder does not exist")
		os.Exit(-1)
	}

	imageDBFolder := filepath.Join(folder, "image", "windowsfilter", "imagedb", "content", "sha256")
	if !folderExists(imageDBFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", imageDBFolder)
		os.Exit(-1)
	}

	layerDBFolder := filepath.Join(folder, "image", "windowsfilter", "layerdb", "sha256")
	if !folderExists(layerDBFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", layerDBFolder)
		os.Exit(-1)
	}
	rawLayerFolder := filepath.Join(folder, "windowsfilter")
	if !folderExists(rawLayerFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", rawLayerFolder)
		os.Exit(-1)
	}
	containerFolder := filepath.Join(folder, "containers")
	if !folderExists(containerFolder) {
		fmt.Printf("Error: incorrect folder structure: expected %s to exist\n", containerFolder)
		os.Exit(-1)
	}

	repoJson := filepath.Join(folder, "image", "windowsfilter", "repositories.json")
	imageMetaDataFolder := filepath.Join(folder, "image", "windowsfilter", "imagedb", "metadata", "sha256")
	if !folderExists(repoJson) {
		fmt.Printf("Error: repositories.json not found! Expected %s to exist.\n", repoJson)
		os.Exit(-1)
	}

	if err := populateImageNameDB(repoJson, imageMetaDataFolder); err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	unreferencedLayers, unreferencedRawLayers, err := verifyImagesAndLayers(rawLayerFolder, layerDBFolder, imageDBFolder, containerFolder, verbose)
	if err != nil {
		fmt.Println(err)
		os.Exit(-1)
	}

	if len(unreferencedLayers) != 0 || len(unreferencedRawLayers) != 0 {
		for _, layer := range unreferencedLayers {
			if remove {
				fmt.Println("Info: Unreferenced layer in layerDB: ", layer, " removing...")
				err = removeDiskLayer(layerDBFolder, layer)
				if err != nil {
					fmt.Println(err)
				}
			} else {
				fmt.Println("Error: Unreferenced layer in layerDB: ", layer)
			}
		}

		for _, layer := range unreferencedRawLayers {
			if remove {
				fmt.Println("Info: Unreferenced layer in windowsfilter: ", layer, " removing...")
				err = removeDiskLayer(rawLayerFolder, layer)
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

func populateImageNameDB(reposJson string, imageMetadataFolder string) error {
	const shaPrefix = "sha256:"
	dat, err := ioutil.ReadFile(reposJson)
	if err != nil {
		return fmt.Errorf("failed to read file %s: %v", reposJson, err)
	}
	var result map[string]interface{}
	if err := json.Unmarshal(dat, &result); err != nil {
		return fmt.Errorf("failed to unmarshal json: %v", err)
	}

	entries := result["Repositories"].(map[string]interface{})
	for _, value := range entries {
		// key is the image/repo name without tags
		// value is another map with full name + tag as key and sha256 as value
		for tag, sha := range value.(map[string]interface{}) {
			if strings.Contains(tag, "@sha256") {
				// there are these extra entries that look like a sha for the tag. Not really sure what they are used for.
				continue
			}
			// Need to remove the sha256: prefix from the sha sums still.
			shaKey := strings.TrimPrefix(sha.(string), shaPrefix)
			imageNameDB[shaSum(shaKey)] = tag
		}
	}
	// This takes care of the 'top level' images. However, we also have a parent-child relation, where (unnamed) images
	// are children of one of the 'top level' images. Hence we need to walk the imagesDB folder and follow these relations.
	files, err := ioutil.ReadDir(imageMetadataFolder)
	if err != nil {
		return fmt.Errorf("failed to read files in %s", imageMetadataFolder)
	}

	childParent := make(map[shaSum]shaSum)
	for _, d := range files {
		if d.IsDir() {
			child := d.Name()
			// parent id should be stored in a file called 'parent' inside the folder
			parentFile := filepath.Join(imageMetadataFolder, d.Name(), "parent")
			dat, err := ioutil.ReadFile(parentFile)
			if err != nil {
				fmt.Println("Error: Unable to read parent info for image id ", child)
				continue
			}
			parent := strings.TrimPrefix(string(dat), shaPrefix)
			childParent[shaSum(child)] = shaSum(parent)
		}
	}

	findLeafImages(childParent)
	return nil
}

func findLeafImages(childParent map[shaSum]shaSum) {
	// there are more optimal ways to do this, but should be okay since the number of images will generally be small.
	for child, parent := range childParent {
		for {
			if val, exists := childParent[parent]; exists {
				parent = val
				continue
			} else if leaf, ok := imageNameDB[parent]; ok {
				imageNameDB[child] = leaf + " (inheritance chain)"
				break
			} else {
				// dangling image
				fmt.Println("Dangling image found: ", parent)
				break
			}
		}
	}
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

func verifyLayersOfImage(imagePath string, sha shaSum, layerMap map[string]*layerDBItem, rawLayerMap map[string]*rawLayerType, verbose bool) error {
	dat, err := ioutil.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("Error: failed to read file %s: %v", imagePath, err)
	}
	image := &imageType{}
	if err := json.Unmarshal(dat, image); err != nil {
		return fmt.Errorf("Error: failed to read JSON contents of %s: %v", imagePath, err)
	}

	if image.OS == "linux" {
		fmt.Printf("WARN: Skipping linux %s\n", imagePath)
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
		if verbose {
			humanReadable := "(sha256:" + string(sha) + ")"
			if name, found := imageNameDB[sha]; found {
				humanReadable = name
			}
			//fmt.Println("Info: Found layer ", diff, " belonging to image ", humanReadable)
			layerSha := shaSum(diff)
			if _, exists := layerImageDB[layerSha]; !exists {
				layerImageDB[layerSha] = make(map[string]struct{})
			}
			layerImageDB[layerSha][humanReadable] = struct{}{}
		}
	}
	return nil
}

func verifyImages(imageDBFolder string, layerMap map[string]*layerDBItem, rawLayerMap map[string]*rawLayerType, verbose bool) error {
	files, err := ioutil.ReadDir(imageDBFolder)
	if err != nil {
		return fmt.Errorf("Error: failed to read files in %s: %v", imageDBFolder, err)
	}
	for _, f := range files {
		if !f.IsDir() {
			imagePath := filepath.Join(imageDBFolder, f.Name())
			err := verifyLayersOfImage(imagePath, shaSum(f.Name()), layerMap, rawLayerMap, verbose)
			if err != nil {
				return err
			}
		}
	}

	if verbose {
		for layerId, images := range layerImageDB {
			fmt.Println("Found layer ", layerId, " belonging to the following images:")
			imageNames := make([]string, 0, len(images))

			for img := range images {
				imageNames = append(imageNames, img)
			}
			sort.Strings(imageNames)

			for _, name := range imageNames {
				fmt.Println("\t", name)
			}
			fmt.Println()
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

func verifyImagesAndLayers(rawLayerFolder, layerDBFolder, imageDBFolder, containerFolder string, verbose bool) ([]string, []string, error) {
	rawLayerMap, err := createRawLayerMap(rawLayerFolder)
	if err != nil {
		return nil, nil, err
	}

	layerMap, err := populateLayerDBMap(layerDBFolder)
	if err != nil {
		return nil, nil, err
	}

	err = verifyImages(imageDBFolder, layerMap, rawLayerMap, verbose)
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
