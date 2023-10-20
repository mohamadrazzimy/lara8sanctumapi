<?php

namespace App\Http\Controllers;

use App\Models\Category;
use Illuminate\Http\Request;

class CategoryController extends Controller
{
    /**
     * Display a listing of the resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function index()
    {
        $category = Category::all();
        return response()->json(
            [
            'category' => $category, 
            'desc'=>'category_found_all',
            'stus' => 'success'
            ]
            );
    }

    /**
     * Show the form for creating a new resource.
     *
     * @return \Illuminate\Http\Response
     */
    public function create()
    {
        //
    }

    /**
     * Store a newly created resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return \Illuminate\Http\Response
     */
    public function store(Request $request)
    {
        $validated = $request->validate([
            'name' => 'required|unique:categories|max:50',
            'image' => 'nullable',
        ]);
        $category_stored = Category::create($validated);

        return response()->json(
            [
            'data' => $category_stored, 
            'desc'=>'category_stored',
            'stus' => 'success'
            ]
            );        
    }

    /**
     * Display the specified resource.
     *
     * @param  $id
     * @return \Illuminate\Http\Response
     */
    public function show($id)
    {
        $category_found= Category::find($id);

        return response()->json(
            [
            'data' => $category_found, 
            'desc'=>'category_found',
            'stus' => 'success'
            ]
            );      

    }

    /**
     * Show the form for editing the specified resource.
     *
     * @param  \App\Models\Category  $category
     * @return \Illuminate\Http\Response
     */
    public function edit(Category $category)
    {
        //
    }

    /**
     * Update the specified resource in storage.
     *
     * @param  \Illuminate\Http\Request  $request
     * @param  $id
     * @return \Illuminate\Http\Response
     */
    public function update(Request $request, $id)
    {
        $validated = $request->validate([
            'name' => 'required|unique:categories|max:50',
            'image'=>'nullable',
        ]);
        $category_store = Category::create($validated);
        $category_updated = Category::where("id", $id)->update($validated);

        return response()->json(
            [
            'data' => $category_updated, 
            'desc'=>'category_updated',
            'stus' => 'success'
            ]
            );               
    }

    /**
     * Remove the specified resource from storage.
     *
     * @param  $id
     * @return \Illuminate\Http\Response
     */
    public function destroy($id)
    {
        $category_destroyed = Category::where("id", $id)->delete();

        return response()->json(
            [
            'data' => $category_destroyed, 
            'desc'=>'category_destroyed',
            'stus' => 'success'
            ]
            );               
    }
}